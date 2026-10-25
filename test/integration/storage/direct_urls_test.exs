defmodule PhoenixKit.Modules.Storage.DirectUrlsTest do
  @moduledoc """
  `Storage.direct_urls/1`: a page links an image straight to the public
  bucket the file route would serve it from, decided from the location rows
  alone, and leaves to the app every image the route would serve itself.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Libraries, Library, Locations, Manager, Profiles}
  alias PhoenixKit.Modules.Storage.Providers.S3
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  @cdn "https://pub-test.r2.dev"

  setup do
    Manager.invalidate_bucket_cache()
    on_exit(&Manager.invalidate_bucket_cache/0)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_direct_#{n}")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, local} =
      Storage.create_bucket(%{
        name: "direct-local-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true
      })

    {:ok, cloud} =
      Storage.create_bucket(%{
        name: "direct-cloud-#{n}",
        provider: "r2",
        bucket_name: "media",
        region: "auto",
        endpoint: "https://acct.r2.cloudflarestorage.com",
        access_key_id: "AKIATEST",
        secret_access_key: "test-secret",
        access_type: "public",
        cdn_url: @cdn,
        enabled: true
      })

    {:ok, library} = Libraries.create_system_library(%{name: "Direct #{n}"})
    {:ok, profile} = Profiles.create_profile(%{name: "Direct #{n}", copies_local: 1})
    {:ok, _} = Profiles.put_bucket(profile, cloud.uuid, %{serve_order: 1})
    {:ok, _} = Profiles.put_bucket(profile, local.uuid, %{serve_order: 2})
    {:ok, library} = Profiles.set_library_profile(library, profile.uuid)

    {:ok, user} =
      Auth.register_user(%{
        "email" => "direct-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    %{
      local: local,
      cloud: cloud,
      library: library,
      profile: Profiles.get_profile(profile.uuid),
      user: user
    }
  end

  # An image with a `medium` variant whose copies are recorded on `buckets`.
  defp image!(ctx, buckets, attrs \\ %{}) do
    n = System.unique_integer([:positive])

    {:ok, file} =
      Storage.create_file(
        Map.merge(
          %{
            original_file_name: "a.jpg",
            file_name: "a.jpg",
            file_path: "direct/#{n}",
            mime_type: "image/jpeg",
            file_type: "image",
            ext: "jpg",
            file_checksum: Ecto.UUID.generate(),
            user_file_checksum: Ecto.UUID.generate(),
            size: 1,
            status: "active",
            user_uuid: ctx.user.uuid,
            library_uuid: ctx.library.uuid
          },
          attrs
        )
      )

    key = "direct/#{n}/a_medium.jpg"

    {:ok, _instance} =
      Storage.create_file_instance(%{
        variant_name: "medium",
        file_name: key,
        mime_type: Map.get(attrs, :mime_type, "image/jpeg"),
        ext: "jpg",
        checksum: "c",
        size: 1,
        processing_status: Map.get(attrs, :processing_status, "completed"),
        file_uuid: file.uuid
      })

    Locations.record_all(key, Enum.map(buckets, & &1.uuid))
    {file.uuid, key}
  end

  # A system library whose profile serves from `buckets`, first to last.
  defp library!(buckets) do
    n = System.unique_integer([:positive])
    {:ok, library} = Libraries.create_system_library(%{name: "Direct lib #{n}"})
    {:ok, profile} = Profiles.create_profile(%{name: "Direct profile #{n}", copies_local: 1})

    buckets
    |> Enum.with_index()
    |> Enum.each(fn {bucket, order} ->
      {:ok, _} = Profiles.put_bucket(profile, bucket.uuid, %{serve_order: order})
    end)

    {:ok, library} = Profiles.set_library_profile(library, profile.uuid)
    library
  end

  defp cloud_attrs(n, extra) do
    Map.merge(
      %{
        name: "direct-extra-#{n}",
        provider: "r2",
        bucket_name: "media",
        region: "auto",
        endpoint: "https://acct.r2.cloudflarestorage.com",
        access_key_id: "AKIATEST",
        secret_access_key: "test-secret",
        access_type: "public",
        cdn_url: @cdn,
        enabled: true
      },
      extra
    )
  end

  # Counts the Ecto query events fired on this process while running `fun`
  # (:telemetry.attach is global, so the handler filters on the test pid).
  defp count_repo_queries(fun) do
    handler_id = "direct-urls-queries-#{inspect(self())}-#{System.unique_integer()}"
    counter = :counters.new(1, [])
    test_pid = self()

    :telemetry.attach(
      handler_id,
      [:phoenix_kit, :test, :repo, :query],
      fn _event, _measurements, _metadata, _config ->
        if self() == test_pid, do: :counters.add(counter, 1, 1)
      end,
      nil
    )

    try do
      fun.()
    after
      :telemetry.detach(handler_id)
    end

    :counters.get(counter, 1)
  end

  defp direct(uuid), do: Map.get(Storage.direct_urls([{uuid, "medium"}]), {uuid, "medium"})

  defp update_bucket!(bucket, attrs) do
    {:ok, _} = Storage.update_bucket(bucket, attrs)
  end

  test "a copy served from a public bucket links to its object", ctx do
    {uuid, key} = image!(ctx, [ctx.cloud, ctx.local])
    assert direct(uuid) == "#{@cdn}/#{key}"
  end

  test "many images in one call, each on its own", ctx do
    {a, key_a} = image!(ctx, [ctx.cloud, ctx.local])
    {b, _key_b} = image!(ctx, [ctx.local])

    assert Storage.direct_urls([{a, "medium"}, {b, "medium"}, {a, "large"}]) ==
             %{{a, "medium"} => "#{@cdn}/#{key_a}"}
  end

  test "a copy the profile serves locally first stays on the app", ctx do
    {uuid, _key} = image!(ctx, [ctx.cloud, ctx.local])
    {:ok, _} = Profiles.put_bucket(ctx.profile, ctx.local.uuid, %{serve_order: 0})
    assert direct(uuid) == nil
  end

  test "a public bucket without a public URL, a private one and a signed one stay on the app",
       ctx do
    {uuid, _key} = image!(ctx, [ctx.cloud, ctx.local])

    update_bucket!(ctx.cloud, %{cdn_url: nil})
    assert direct(uuid) == nil

    update_bucket!(Storage.get_bucket(ctx.cloud.uuid), %{cdn_url: @cdn, access_type: "private"})
    assert direct(uuid) == nil

    update_bucket!(Storage.get_bucket(ctx.cloud.uuid), %{access_type: "signed"})
    assert direct(uuid) == nil
  end

  # The query-count block covers a disabled bucket ranked first and skipped
  # for the next one; this is the case with nothing to fall through to.
  test "a copy recorded only on a disabled bucket stays on the app", ctx do
    n = System.unique_integer([:positive])

    {:ok, disabled} =
      Storage.create_bucket(cloud_attrs(n, %{name: "direct-off-#{n}", enabled: false}))

    {uuid, _key} = image!(ctx, [disabled])
    assert direct(uuid) == nil
  end

  test "a backup copy is never linked", ctx do
    {uuid, _key} = image!(ctx, [ctx.cloud])
    {:ok, _} = Profiles.put_bucket(ctx.profile, ctx.cloud.uuid, %{role: "backup"})
    assert direct(uuid) == nil
  end

  test "a variant not made yet, a trashed file and a non-inline type stay on the app", ctx do
    {pending, _} = image!(ctx, [ctx.cloud], %{processing_status: "pending"})
    {trashed, _} = image!(ctx, [ctx.cloud], %{status: "trashed"})
    {svg, _} = image!(ctx, [ctx.cloud], %{mime_type: "image/svg+xml"})

    assert Storage.direct_urls([{pending, "medium"}, {trashed, "medium"}, {svg, "medium"}]) ==
             %{}
  end

  test "a file with an image edit pending or failed stays on the app", ctx do
    for state <- ["pending", "failed"] do
      {uuid, _key} = image!(ctx, [ctx.cloud])
      assert direct(uuid) != nil

      {1, _} =
        Repo.update_all(from(f in PhoenixKit.Modules.Storage.File, where: f.uuid == ^uuid),
          set: [edit_state: state]
        )

      assert direct(uuid) == nil, "edit_state #{state} was linked"
    end
  end

  test "a file in a private library stays on the app", ctx do
    {uuid, _key} = image!(ctx, [ctx.cloud])
    assert direct(uuid) != nil

    {1, _} =
      Repo.update_all(from(l in Library, where: l.uuid == ^ctx.library.uuid),
        set: [visibility: "private"]
      )

    assert direct(uuid) == nil
  end

  test "a system-managed file stays on the app", ctx do
    {parent, _key} = image!(ctx, [ctx.cloud])

    {child, _key} =
      image!(ctx, [ctx.cloud], %{system_managed: true, parent_file_uuid: parent})

    assert direct(parent) != nil
    assert direct(child) == nil
  end

  test "a Media file is ranked by the Default profile", ctx do
    default = Profiles.get_profile(Profiles.default_uuid())
    {:ok, _} = Profiles.put_bucket(default, ctx.local.uuid, %{serve_order: 0})
    {:ok, _} = Profiles.put_bucket(default, ctx.cloud.uuid, %{serve_order: 1})

    media = %{library_uuid: Libraries.media_uuid()}
    {in_media, key} = image!(ctx, [ctx.cloud, ctx.local], media)
    {in_library, library_key} = image!(ctx, [ctx.cloud, ctx.local])

    # The Default profile serves from the local bucket first, the library's
    # own profile from the cloud one: each file follows its own.
    assert direct(in_media) == nil
    assert direct(in_library) == "#{@cdn}/#{library_key}"

    {:ok, _} = Profiles.put_bucket(default, ctx.local.uuid, %{serve_order: 2})
    assert direct(in_media) == "#{@cdn}/#{key}"
  end

  test "a public S3-compatible bucket without a cdn_url links to its native object URL",
       ctx do
    n = System.unique_integer([:positive])

    {:ok, aws} =
      Storage.create_bucket(
        cloud_attrs(n, %{
          name: "direct-aws-#{n}",
          provider: "s3",
          bucket_name: "native-bucket",
          region: "eu-west-1",
          endpoint: nil,
          cdn_url: nil
        })
      )

    {:ok, minio} =
      Storage.create_bucket(
        cloud_attrs(n, %{
          name: "direct-minio-#{n}",
          provider: "s3",
          bucket_name: "minio-bucket",
          region: "us-east-1",
          endpoint: "https://minio.example.com",
          cdn_url: nil
        })
      )

    {a, key_a} = image!(%{ctx | library: library!([aws, ctx.local])}, [aws, ctx.local])
    {b, key_b} = image!(%{ctx | library: library!([minio, ctx.local])}, [minio, ctx.local])

    # Exactly what the file route redirects to: the provider's own URL.
    assert direct(a) == "https://native-bucket.s3.eu-west-1.amazonaws.com/#{key_a}"
    assert direct(a) == S3.public_url(aws, key_a)
    assert direct(b) == "https://minio.example.com/minio-bucket/#{key_b}"
    assert direct(b) == S3.public_url(minio, key_b)
  end

  test "an empty list, a non-uuid, a differently spelled uuid and duplicates", ctx do
    {uuid, key} = image!(ctx, [ctx.cloud])

    assert Storage.direct_urls([]) == %{}
    assert Storage.direct_urls([{"not-a-uuid", "medium"}, {"", "medium"}]) == %{}

    # Results are keyed by the canonical lower-case uuid.
    assert Storage.direct_urls([{String.upcase(uuid), "medium"}]) == %{}

    # A variant that is not a string is left out, not a cast error for the
    # whole batch.
    assert Storage.direct_urls([{uuid, :medium}, {uuid, nil}, {uuid, "medium"}]) ==
             %{{uuid, "medium"} => "#{@cdn}/#{key}"}

    assert Storage.direct_urls([
             {%{}, "medium"},
             {[], "medium"},
             {nil, "medium"},
             {123, "medium"},
             {uuid, "medium"}
           ]) == %{{uuid, "medium"} => "#{@cdn}/#{key}"}

    assert Storage.direct_urls([
             {"not-a-uuid", "medium"},
             {uuid, "medium"},
             {uuid, "medium"},
             {uuid, "medium"}
           ]) == %{{uuid, "medium"} => "#{@cdn}/#{key}"}
  end

  describe "query count" do
    # A disabled bucket the rows still name is the case outside the pool of
    # enabled buckets: it used to cost a lookup per file.
    setup ctx do
      n = System.unique_integer([:positive])

      {:ok, disabled} =
        Storage.create_bucket(cloud_attrs(n, %{name: "direct-off-#{n}", enabled: false}))

      %{disabled: disabled, buckets: [disabled, ctx.cloud, ctx.local]}
    end

    defp pairs_in(ctx, libraries, per_library) do
      for library <- libraries, _ <- 1..per_library do
        {uuid, _key} = image!(%{ctx | library: library}, ctx.buckets)
        {uuid, "medium"}
      end
    end

    test "does not grow with the files or the libraries", ctx do
      few = pairs_in(ctx, [library!(ctx.buckets)], 1)
      many = pairs_in(ctx, for(_ <- 1..5, do: library!(ctx.buckets)), 3)

      # The first call warms the cache of enabled buckets.
      assert map_size(Storage.direct_urls(few)) == 1

      few_count = count_repo_queries(fn -> assert map_size(Storage.direct_urls(few)) == 1 end)
      many_count = count_repo_queries(fn -> assert map_size(Storage.direct_urls(many)) == 15 end)

      # Instances, private libraries, ranked locations, buckets outside the
      # pool (the disabled one): four, whatever the batch.
      assert {few_count, many_count} == {4, 4}
    end

    test "a cold bucket cache costs one more, once", ctx do
      pairs = pairs_in(ctx, for(_ <- 1..3, do: library!(ctx.buckets)), 2)

      Manager.invalidate_bucket_cache()
      assert count_repo_queries(fn -> Storage.direct_urls(pairs) end) == 5
      assert count_repo_queries(fn -> Storage.direct_urls(pairs) end) == 4
    end

    test "Media files add no library query and no bucket query when all are in the pool",
         ctx do
      media = %{library_uuid: Libraries.media_uuid()}
      {uuid, _key} = image!(ctx, [ctx.cloud, ctx.local], media)
      pairs = [{uuid, "medium"}]

      Storage.direct_urls(pairs)

      # Instances and ranked locations only: Media is public without a
      # query, and every bucket the rows name is in the pool.
      assert count_repo_queries(fn -> Storage.direct_urls(pairs) end) == 2
    end
  end

  test "ranked_all/1 ranks each object as ranked/2 does", ctx do
    {a, key_a} = image!(ctx, [ctx.cloud, ctx.local])
    {b, key_b} = image!(ctx, [ctx.local])

    assert Locations.ranked_all([{key_a, a}, {key_b, b}, {key_a, b}]) == %{
             {key_a, a} => Locations.ranked(key_a, a),
             {key_b, b} => Locations.ranked(key_b, b)
           }
  end
end
