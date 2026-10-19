defmodule PhoenixKit.Modules.Storage.HiddenLibraryTest do
  @moduledoc """
  A hidden system library (`Libraries.create_system_library(attrs, hidden: true)`):
  a module's own store. It is not listed with the site's libraries, its files and
  folders are left out of every site listing, its files get only expiring URLs,
  and only their uploader (and an Owner/Admin) may read them — a holder of
  `media` + `media.view_all` may not. Dedup works inside it as in any library,
  and never reaches into it from outside.
  """

  use PhoenixKit.DataCase, async: false

  import Ecto.Query, only: [from: 2]
  import Plug.Test

  alias PhoenixKit.Modules.Storage

  alias PhoenixKit.Modules.Storage.{
    Audit,
    Bucket,
    ImageEditing,
    Libraries,
    Library,
    Profiles,
    Reconciler,
    RepairLog,
    URLSigner
  }

  alias PhoenixKit.Modules.Storage.Jobs.{PurgeLibrary, Reconcile}

  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKitWeb.FileController

  @media Libraries.media_uuid()
  @buckets_cache :phoenix_kit_buckets_cache

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_hidden_library_#{n}")
    # Only this test's bucket takes uploads, whatever the database already holds.
    Repo.update_all(Bucket, set: [enabled: false])

    {:ok, bucket} =
      Storage.create_bucket(%{
        name: "hidden-library-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true,
        priority: 0
      })

    start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    on_exit(fn ->
      :persistent_term.erase(@buckets_cache)
      File.rm_rf(root)
    end)

    {:ok, manager_role} = Roles.create_role(%{name: "Managers #{n}"})

    for key <- ~w(media media.view_all media.manage),
        do: {:ok, _} = Permissions.grant_permission(manager_role.uuid, key)

    {:ok, hidden} =
      Libraries.create_system_library(%{name: "Assistant #{n}", slug: "assistant-#{n}"},
        hidden: true
      )

    %{
      n: n,
      bucket: bucket,
      hidden: hidden,
      uploader: user!("uploader"),
      manager: user!("manager", manager_role)
    }
  end

  defp user!(tag, role \\ nil) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "hidden-#{tag}-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    if role, do: {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  defp scope(user), do: Scope.for_user(Repo.get!(Auth.User, user.uuid))

  defp store(user, library_uuid, content) do
    source = Path.join(System.tmp_dir!(), "pk_hidden_src_#{System.unique_integer([:positive])}")
    File.write!(source, content)
    checksum = :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower)
    opts = if library_uuid, do: [library_uuid: library_uuid], else: []

    {result, _log} =
      ExUnit.CaptureLog.with_log(fn ->
        Storage.store_file_in_buckets(source, "image", user.uuid, checksum, "jpg", "a.jpg", opts)
      end)

    File.rm(source)
    result
  end

  defp uuids(rows), do: Enum.map(rows, & &1.uuid)

  describe "creating one" do
    test "hidden: true makes a private system library; without it nothing changes", %{
      hidden: hidden,
      n: n
    } do
      assert %Library{kind: "system", visibility: "private"} = hidden
      assert Libraries.hidden?(hidden)
      assert Libraries.hidden?(hidden.uuid)
      assert Libraries.system_library?(hidden.uuid)

      {:ok, plain} = Libraries.create_system_library(%{name: "Plain #{n}"})
      assert plain.visibility == "site"
      refute Libraries.hidden?(plain)
      refute Libraries.hidden?(@media)
      refute Libraries.private?(plain.uuid)
    end

    test "a visibility in the attrs (what a form posts) does not hide a library", %{n: n} do
      {:ok, library} =
        Libraries.create_system_library(%{"name" => "Posted #{n}", "visibility" => "private"})

      assert library.visibility == "site"
      refute Libraries.hidden?(library)
    end

    test "a hidden one is made with the slug it is asked for, or not at all", %{n: n} do
      assert {:error, changeset} =
               Libraries.create_system_library(%{name: "No slug #{n}"}, hidden: true)

      assert "can't be blank" in errors_on(changeset).slug

      # A taken slug is refused, not replaced by "<slug>-2" the module would not find.
      {:ok, site} = Libraries.create_system_library(%{name: "Taken #{n}"})

      assert {:error, changeset} =
               Libraries.create_system_library(%{name: "Other #{n}", slug: site.slug},
                 hidden: true
               )

      assert errors_on(changeset).slug != []
      refute Libraries.get_hidden_library_by_slug(site.slug)

      # A site library still picks a free slug when none is given.
      {:ok, again} = Libraries.create_system_library(%{name: "Taken-#{n}"})
      assert again.slug == site.slug <> "-2"
    end

    test "audit: false leaves its creation out of the Storage history", %{hidden: hidden, n: n} do
      created = fn library ->
        Repo.exists?(
          from(e in PhoenixKit.Activity.Entry,
            where:
              e.resource_uuid == ^to_string(library.uuid) and
                e.action == "storage.library.created"
          )
        )
      end

      assert created.(hidden)

      {:ok, quiet} =
        Libraries.create_system_library(%{name: "Quiet #{n}", slug: "quiet-#{n}"},
          hidden: true,
          audit: false
        )

      refute created.(quiet)
    end

    test "after its creation, nothing names a hidden library in the Storage history", %{
      hidden: hidden,
      n: n
    } do
      {:ok, renamed} = Libraries.rename_library(hidden, "Renamed #{n}")
      {:ok, _} = Libraries.put_setting(renamed, :annotated_thumbnails, true)
      {:ok, _} = Libraries.delete_library(renamed)

      actions =
        Repo.all(
          from(e in PhoenixKit.Activity.Entry,
            where: e.resource_uuid == ^to_string(hidden.uuid),
            select: e.action
          )
        )

      assert actions == ["storage.library.created"]
    end
  end

  describe "listing" do
    test "it is not one of the site's libraries, but its owner finds it by slug", %{
      hidden: hidden
    } do
      refute hidden.uuid in uuids(Libraries.list_system_libraries())

      refute hidden.uuid in Enum.map(
               Libraries.list_system_libraries_with_stats(),
               & &1.library.uuid
             )

      refute Libraries.get_system_library(hidden.uuid)
      refute Libraries.get_system_library_with_stats(hidden.uuid)
      refute Libraries.get_system_library_by_slug(hidden.slug)

      assert Libraries.get_library(hidden.uuid).uuid == hidden.uuid
      assert Libraries.get_hidden_library_by_slug(hidden.slug).uuid == hidden.uuid
      refute Libraries.get_hidden_library_by_slug("no-such-library")
      refute Libraries.get_hidden_library_by_slug(nil)
    end

    test "a site library is not found as a hidden one", %{n: n} do
      {:ok, plain} = Libraries.create_system_library(%{name: "Site #{n}"})
      refute Libraries.get_hidden_library_by_slug(plain.slug)
    end

    test "its files and folders stay out of listings that name no library", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, file} = store(uploader, hidden.uuid, "hidden listing #{n}")
      assert file.library_uuid == hidden.uuid

      {:ok, folder} =
        Storage.create_folder(%{name: "hidden-folder-#{n}", library_uuid: hidden.uuid})

      {files, _} = Storage.list_files_in_scope(nil, per_page: 1000)
      refute file.uuid in uuids(files)

      refute folder.uuid in uuids(Storage.list_folders(nil, nil))
      refute folder.uuid in Enum.map(Storage.list_folder_tree(nil), & &1.folder.uuid)
      assert [] == Storage.search_folders("hidden-folder-#{n}", nil, nil)

      # Named explicitly (the module that owns it), it is listed.
      {files, _} = Storage.list_files_in_scope(nil, library_uuid: hidden.uuid)
      assert file.uuid in uuids(files)

      assert folder.uuid in Enum.map(
               Storage.list_folder_tree(nil, library_uuid: hidden.uuid),
               & &1.folder.uuid
             )
    end
  end

  describe "access" do
    test "a holder of media.view_all can neither read nor edit its files; the uploader and an Admin can",
         %{hidden: hidden, uploader: uploader, manager: manager, n: n} do
      {:ok, file} = store(uploader, hidden.uuid, "hidden access #{n}")
      {admin, _token} = PhoenixKitWeb.ConnCase.create_admin_user()

      refute Libraries.can?(scope(manager), file, :read)
      refute Libraries.can?(scope(manager), file, :edit)
      refute Storage.authorized_url(scope(manager), file, "original")

      assert Libraries.can?(scope(uploader), file, :read)
      # Owner/Admin read any file of Storage (`Scope.system_role?/1`), as before.
      assert Libraries.can?(scope(admin), file, :read)
    end

    test "a holder of media.view_all still edits a site library's files", %{
      uploader: uploader,
      manager: manager,
      n: n
    } do
      {:ok, plain} = Libraries.create_system_library(%{name: "Editable #{n}"})
      {:ok, file} = store(uploader, plain.uuid, "site library edit #{n}")
      assert Libraries.can?(scope(manager), file, :edit)
    end

    test "its files take only an expiring URL; the permanent one is refused", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, file} = store(uploader, hidden.uuid, "hidden url #{n}")
      assert Libraries.private_file?(file)

      permanent = URLSigner.generate_token(file.uuid, "original")

      conn =
        FileController.show(conn(:get, "/"), %{
          "file_uuid" => file.uuid,
          "variant" => "original",
          "token" => permanent
        })

      assert conn.status == 401

      # The uploader's URL is a time-window one, and it serves.
      url = Storage.authorized_url(scope(uploader), file, "original")
      [token] = url |> String.split("/") |> Enum.take(-1)
      assert "w" <> _ = token

      conn =
        FileController.show(conn(:get, "/"), %{
          "file_uuid" => file.uuid,
          "variant" => "original",
          "token" => token
        })

      assert conn.status == 200
    end

    test "the edit gate (unedited original, burn-in) refuses a holder of media.view_all",
         %{hidden: hidden, uploader: uploader, manager: manager, n: n} do
      {:ok, plain} = Libraries.create_system_library(%{name: "Edits #{n}"})
      {:ok, site_file} = store(uploader, plain.uuid, "site edit gate #{n}")
      {:ok, hidden_file} = store(uploader, hidden.uuid, "hidden edit gate #{n}")

      assert ImageEditing.can_edit?(site_file, scope(manager))
      refute ImageEditing.can_edit?(hidden_file, scope(manager))
      assert ImageEditing.can_edit?(hidden_file, scope(uploader))
    end

    test "the unedited original of a hidden file is a 404 for a holder of media.view_all",
         %{hidden: hidden, uploader: uploader, manager: manager, n: n} do
      {:ok, plain} = Libraries.create_system_library(%{name: "Unedited #{n}"})
      site_file = edited!(uploader, plain.uuid, "site unedited #{n}")
      hidden_file = edited!(uploader, hidden.uuid, "hidden unedited #{n}")

      unedited = fn user, file ->
        conn(:get, "/")
        |> Plug.Conn.assign(:phoenix_kit_current_user, user)
        |> FileController.unedited(%{"file_uuid" => file.uuid})
      end

      assert unedited.(manager, site_file).status == 200
      assert unedited.(manager, hidden_file).status == 404
      assert unedited.(uploader, hidden_file).status == 200
    end
  end

  # A file of `library_uuid` with an unedited original behind it (what an image
  # edit leaves): a second upload made into the first one's hidden backup.
  defp edited!(user, library_uuid, content) do
    {:ok, file} = store(user, library_uuid, content)
    {:ok, original} = store(user, library_uuid, content <> " original")

    original
    |> Ecto.Changeset.change(
      parent_file_uuid: file.uuid,
      system_managed: true,
      file_name: ImageEditing.backup_name()
    )
    |> Repo.update!()

    file |> Ecto.Changeset.change(original_file_uuid: original.uuid) |> Repo.update!()
  end

  describe "dedup" do
    test "the same bytes uploaded to Media after the hidden library give a new, visible file",
         %{hidden: hidden, uploader: uploader, n: n} do
      content = "reverse dedup #{n}"
      {:ok, hidden_file} = store(uploader, hidden.uuid, content)

      assert {:ok, media_file} = store(uploader, nil, content)
      assert media_file.uuid != hidden_file.uuid
      assert media_file.library_uuid == @media

      {files, _} = Storage.list_files_in_scope(nil, library_uuid: @media, per_page: 1000)
      assert media_file.uuid in uuids(files)
      refute Libraries.private_file?(media_file)

      # And through the plain `store_file/2`, which names no library.
      source = Path.join(System.tmp_dir!(), "pk_hidden_plain_#{n}")
      File.write!(source, content)

      {{:ok, plain}, _log} =
        ExUnit.CaptureLog.with_log(fn ->
          Storage.store_file(source,
            filename: "a.jpg",
            content_type: "image/jpeg",
            size_bytes: byte_size(content),
            user_uuid: uploader.uuid
          )
        end)

      File.rm(source)
      assert plain.library_uuid == @media
      refute plain.uuid == hidden_file.uuid
    end

    test "another uploader's Media upload of the same bytes is not cloned from the hidden file",
         %{hidden: hidden, uploader: uploader, manager: manager, n: n} do
      content = "cross user #{n}"
      {:ok, hidden_file} = store(uploader, hidden.uuid, content)

      assert {:ok, other} = store(manager, nil, content)
      assert other.library_uuid == @media
      refute other.file_path == hidden_file.file_path
    end

    test "store_file/2 with only a hidden copy of the bytes gives a new Media file", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      content = "only hidden #{n}"
      {:ok, hidden_file} = store(uploader, hidden.uuid, content)

      source = Path.join(System.tmp_dir!(), "pk_hidden_only_#{n}")
      File.write!(source, content)

      {{:ok, plain}, _log} =
        ExUnit.CaptureLog.with_log(fn ->
          Storage.store_file(source,
            filename: "a.jpg",
            content_type: "image/jpeg",
            size_bytes: byte_size(content),
            user_uuid: uploader.uuid
          )
        end)

      File.rm(source)
      assert plain.uuid != hidden_file.uuid
      assert plain.library_uuid == @media
      refute Libraries.private_file?(plain)
      assert Storage.get_file(hidden_file.uuid).library_uuid == hidden.uuid
    end

    test "inside the hidden library a second upload is the same file", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      content = "direct dedup #{n}"
      {:ok, first} = store(uploader, hidden.uuid, content)

      assert {:ok, again, :duplicate} = store(uploader, hidden.uuid, content)
      assert again.uuid == first.uuid
      assert again.library_uuid == hidden.uuid
    end
  end

  describe "orphan cleanup" do
    test "a hidden library's unreferenced file is not an orphan and is not queued", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, hidden_file} = store(uploader, hidden.uuid, "hidden orphan #{n}")
      {:ok, media_file} = store(uploader, nil, "media orphan #{n}")

      # Media's own unreferenced file is the control: it is an orphan.
      assert media_file.uuid in uuids(Storage.find_orphaned_files())
      assert Storage.file_orphaned?(media_file.uuid)

      refute hidden_file.uuid in uuids(Storage.find_orphaned_files())
      refute hidden_file.uuid in uuids(Storage.find_orphaned_files(library_uuid: hidden.uuid))
      assert Storage.find_orphaned_files(library_uuid: hidden.uuid) == []
      assert Storage.count_orphaned_files(nil, library_uuid: hidden.uuid) == 0
      refute Storage.file_orphaned?(hidden_file.uuid)

      # "Delete all orphaned" queues what find_orphaned_files returns.
      assert hidden_file.uuid not in uuids(Storage.find_orphaned_files(limit: 100_000))
    end
  end

  describe "Settings pages, which name the site's libraries" do
    test "Health does not list a hidden library's stale file, but counts it", %{
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, plain} = Libraries.create_system_library(%{name: "Stale site #{n}"})
      {:ok, site_file} = store(uploader, plain.uuid, "stale site #{n}")
      {:ok, hidden_file} = store(uploader, hidden.uuid, "stale hidden #{n}")

      for file <- [site_file, hidden_file],
          do: Repo.update!(Ecto.Changeset.change(file, status: "active", placed_revision: 0))

      listed = Enum.map(Reconciler.stale_files(), & &1.file_uuid)
      assert site_file.uuid in listed
      refute hidden_file.uuid in listed
      assert Reconciler.stale_count() == 2
    end

    test "a bucket's contents count the hidden library with the private ones, unnamed", %{
      bucket: bucket,
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, _} = store(uploader, nil, "bucket media #{n}")
      {:ok, _} = store(uploader, hidden.uuid, "bucket hidden #{n}")

      contents = Storage.bucket_contents(bucket.uuid)
      refute hidden.uuid in Enum.map(contents.libraries, & &1.uuid)
      refute hidden.name in Enum.map(contents.libraries, & &1.name)
      assert @media in Enum.map(contents.libraries, & &1.uuid)
      assert contents.personal.libraries == 1
      assert contents.personal.files == 1
      assert contents.files == 2
    end

    test "a profile's users count the hidden library without naming it", %{n: n} do
      {:ok, profile} = Profiles.create_profile(%{name: "Hidden profile #{n}"})

      {:ok, hidden} =
        Libraries.create_system_library(
          %{name: "On profile #{n}", slug: "on-profile-#{n}", storage_profile_uuid: profile.uuid},
          hidden: true
        )

      {:ok, site} =
        Libraries.create_system_library(%{
          name: "Site on profile #{n}",
          storage_profile_uuid: profile.uuid
        })

      assert %{names: [site.name], user_libraries: 1} ==
               Profiles.library_names_using(profile.uuid)

      refute hidden.name in Profiles.library_names_using(Profiles.default_uuid()).names
    end

    test "job titles and the repair log do not name it", %{
      bucket: bucket,
      hidden: hidden,
      uploader: uploader,
      n: n
    } do
      {:ok, plain} = Libraries.create_system_library(%{name: "Titled #{n}"})

      for job <- [Reconcile, PurgeLibrary] do
        assert job.title(%{}, {"library", plain.uuid}) =~ plain.name
        refute job.title(%{}, {"library", hidden.uuid}) =~ hidden.name
      end

      # The repair log writes nothing about a private library's file (`Audit.log_damage/3`).
      {:ok, file} = store(uploader, hidden.uuid, "repair log #{n}")

      Audit.log_damage(
        file,
        [%{name: "original", bucket: bucket, path: "k/o.bin", result: :not_found}],
        actor_uuid: uploader.uuid
      )

      assert %{rows: []} = RepairLog.list(file_uuid: file.uuid)
    end
  end
end
