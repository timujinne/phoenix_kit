defmodule PhoenixKit.Modules.Storage.DirectUrlsTest do
  @moduledoc """
  `Storage.direct_urls/1`: a page links an image straight to the public
  bucket the file route would serve it from, decided from the location rows
  alone, and leaves to the app every image the route would serve itself.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Libraries, Library, Locations, Profiles}
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  @cache :phoenix_kit_buckets_cache
  @cdn "https://pub-test.r2.dev"

  setup do
    :persistent_term.erase(@cache)
    on_exit(fn -> :persistent_term.erase(@cache) end)
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

  test "a file in a private library or with an edit in progress stays on the app", ctx do
    {uuid, _key} = image!(ctx, [ctx.cloud])

    {1, _} =
      Repo.update_all(from(f in PhoenixKit.Modules.Storage.File, where: f.uuid == ^uuid),
        set: [edit_state: "pending"]
      )

    assert direct(uuid) == nil

    {other, _key} = image!(ctx, [ctx.cloud])

    {1, _} =
      Repo.update_all(from(l in Library, where: l.uuid == ^ctx.library.uuid),
        set: [visibility: "private"]
      )

    assert direct(other) == nil
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
