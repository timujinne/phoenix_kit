defmodule PhoenixKit.Modules.Storage.PublicLibrariesTest do
  @moduledoc """
  Public user libraries: who may create one (the `storage.public_library`
  permission, and only at creation), that anyone, signed in or not, may read what
  is in one and nothing else, that it never lands in site media, that its files get
  ordinary links while it is public and expiring ones once it is suspended, and the
  admin's suspend and restore with their history entries.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Modules.Storage.{Libraries, Library}
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Users.Auth.Scope

  setup do
    {:ok, _} = Settings.update_boolean_setting("storage_user_libraries_enabled", true)
    {:ok, _} = Settings.update_setting("storage_user_library_limit", "10")

    n = System.unique_integer([:positive])

    {:ok, plain} = Roles.create_role(%{name: "Plain #{n}"})

    for key <- ~w(storage storage.create_library),
        do: {:ok, _} = Permissions.grant_permission(plain.uuid, key)

    {:ok, publisher} = Roles.create_role(%{name: "Publishers #{n}"})

    for key <- ~w(storage storage.create_library storage.public_library),
        do: {:ok, _} = Permissions.grant_permission(publisher.uuid, key)

    %{plain: plain, publisher: publisher}
  end

  defp user!(role \\ nil) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "public-libs-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    if role, do: {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  defp admin! do
    admin = user!()
    {:ok, _} = Roles.assign_role(admin, "Admin")
    Repo.get!(Auth.User, admin.uuid)
  end

  defp scope(user), do: Scope.for_user(Repo.get!(Auth.User, user.uuid))
  defp anonymous, do: Scope.for_user(nil)

  defp create!(user, visibility \\ nil, name \\ "Lib #{System.unique_integer([:positive])}") do
    attrs = %{"name" => name}
    attrs = if visibility, do: Map.put(attrs, "visibility", visibility), else: attrs
    {:ok, library} = Libraries.create_user_library(scope(user), attrs)
    library
  end

  defp file!(user, library_uuid) do
    n = System.unique_integer([:positive])

    attrs = %{
      original_file_name: "p#{n}.png",
      file_name: "f-#{n}.png",
      file_path: "x/#{n}.png",
      mime_type: "image/png",
      file_type: "image",
      ext: "png",
      file_checksum: Ecto.UUID.generate(),
      user_file_checksum: Ecto.UUID.generate(),
      size: 1,
      status: "active",
      user_uuid: user.uuid
    }

    attrs = if library_uuid, do: Map.put(attrs, :library_uuid, library_uuid), else: attrs
    {:ok, file} = Storage.create_file(attrs)
    file
  end

  defp entries(action) do
    Repo.all(
      from e in Entry,
        where: e.module == "storage" and e.action == ^action,
        order_by: [asc: e.inserted_at]
    )
  end

  describe "creating" do
    test "a library is private unless asked", %{plain: plain} do
      user = user!(plain)

      assert %Library{visibility: "private"} = create!(user)
      assert %Library{visibility: "private"} = create!(user, "private")
    end

    test "a public one needs the storage.public_library permission", %{plain: plain} do
      user = user!(plain)

      assert {:error, :not_allowed} =
               Libraries.create_user_library(scope(user), %{
                 "name" => "Gallery",
                 "visibility" => "public"
               })

      assert Libraries.list_user_libraries(user.uuid) == []
      refute Libraries.may_create_public_library?(scope(user))
    end

    test "with it, a public library is made, public, and written to the history", %{
      publisher: publisher
    } do
      user = user!(publisher)
      assert Libraries.may_create_public_library?(scope(user))

      library = create!(user, "public", "Gallery")

      assert library.visibility == "site"
      assert library.kind == "user"
      assert Libraries.public?(library)
      assert Libraries.public?(library.uuid)

      assert [%Entry{actor_uuid: actor, metadata: %{"name" => "Gallery"}} | _] =
               entries("storage.library_published")

      assert to_string(actor) == user.uuid
    end

    test "anything but private and public is refused", %{publisher: publisher} do
      user = user!(publisher)

      for value <- ["site", "everyone", "", 1] do
        assert {:error, :not_allowed} =
                 Libraries.create_user_library(scope(user), %{
                   "name" => "X",
                   "visibility" => value
                 })
      end

      assert Libraries.list_user_libraries(user.uuid) == []
    end

    test "a library made without a choice is private even though the field's default is site", %{
      plain: plain
    } do
      library = create!(user!(plain))

      assert Repo.get!(Library, library.uuid).visibility == "private"
      refute Libraries.public?(library)
    end

    test "the personal library the host makes is private" do
      user = user!()
      {:ok, library} = Libraries.ensure_personal_library(user.uuid)

      assert library.visibility == "private"
    end
  end

  describe "reading" do
    setup %{publisher: publisher} do
      owner = user!(publisher)
      public = create!(owner, "public", "Public")
      private = create!(owner, nil, "Private")

      %{
        owner: owner,
        public: public,
        private: private,
        in_public: file!(owner, public.uuid),
        in_private: file!(owner, private.uuid),
        in_media: file!(owner, nil)
      }
    end

    test "anyone reads a file of a public library, signed in or not", ctx do
      assert Libraries.can?(nil, ctx.in_public, :read)
      assert Libraries.can?(anonymous(), ctx.in_public, :read)
      assert Libraries.can?(scope(user!()), ctx.in_public, :read)
      assert Libraries.can?(scope(ctx.owner), ctx.in_public, :read)
    end

    test "and nothing else: a private library's and Media's files stay closed", ctx do
      stranger = scope(user!())

      for file <- [ctx.in_private, ctx.in_media], who <- [nil, anonymous(), stranger] do
        refute Libraries.can?(who, file, :read)
      end

      assert Libraries.can?(scope(ctx.owner), ctx.in_private, :read)
    end

    test "reading is all the world gets: editing stays with the owner and managers", ctx do
      stranger = scope(user!())

      refute Libraries.can?(nil, ctx.in_public, :edit)
      refute Libraries.can?(anonymous(), ctx.in_public, :edit)
      refute Libraries.can?(stranger, ctx.in_public, :edit)
      assert Libraries.can?(scope(ctx.owner), ctx.in_public, :edit)
    end

    test "can_read_library?/2 says the same of the library as a whole", ctx do
      stranger = scope(user!())

      for who <- [nil, anonymous(), stranger] do
        assert Libraries.can_read_library?(who, ctx.public)
        refute Libraries.can_read_library?(who, ctx.private)
      end

      assert Libraries.can_read_library?(scope(ctx.owner), ctx.private)
      assert Libraries.can_read_library?(scope(admin!()), ctx.private)
      refute Libraries.can_read_library?(nil, nil)
    end

    test "Media is not a public library, and junk is not a library", %{in_media: _} do
      refute Libraries.public?(Libraries.media_uuid())
      refute Libraries.public?(nil)
      refute Libraries.public?("not-a-uuid")
      refute Libraries.public?(Ecto.UUID.generate())
    end

    test "a public library in the trash is not public", ctx do
      {:ok, _} = Libraries.trash_library(scope(ctx.owner), ctx.public)

      refute Libraries.public?(ctx.public.uuid)
      refute Libraries.can?(nil, ctx.in_public, :read)
    end

    # Trashing leaves the files `active`; the permanent links they already have
    # are refused because the library answers as private.
    test "and its files answer as private, so their permanent links stop serving", ctx do
      refute Libraries.private_file?(ctx.in_public)

      {:ok, trashed} = Libraries.trash_library(scope(ctx.owner), ctx.public)

      assert Libraries.private_file?(ctx.in_public)
      assert Libraries.private_among([ctx.public.uuid]) == [ctx.public.uuid]

      {:ok, _} = Libraries.restore_library(scope(ctx.owner), trashed)
      refute Libraries.private_file?(ctx.in_public)
    end

    test "its files get ordinary links, a private library's expiring ones", ctx do
      refute Libraries.private_file?(ctx.in_public)
      assert Libraries.private_file?(ctx.in_private)
      assert Libraries.private_among([ctx.public.uuid, ctx.private.uuid]) == [ctx.private.uuid]
    end
  end

  describe "site media" do
    test "a user library, public or private, never appears in the site's listings", %{
      publisher: publisher
    } do
      owner = user!(publisher)
      public = create!(owner, "public")
      private = create!(owner)

      site = file!(owner, nil)
      in_public = file!(owner, public.uuid)
      in_private = file!(owner, private.uuid)
      ids = [site.uuid, in_public.uuid, in_private.uuid]

      shown =
        from(f in StorageFile, where: f.uuid in ^ids)
        |> Libraries.exclude_user_libraries()
        |> Repo.all()
        |> Enum.map(& &1.uuid)

      assert shown == [site.uuid]

      # The name it had when every user library was private still works.
      assert from(f in StorageFile, where: f.uuid in ^ids)
             |> Libraries.exclude_private()
             |> Repo.all()
             |> Enum.map(& &1.uuid) == [site.uuid]

      {files, _total} = Storage.list_files_in_scope(nil, per_page: 100)
      listed = Enum.map(files, & &1.uuid)
      assert site.uuid in listed
      refute in_public.uuid in listed
      refute in_private.uuid in listed
    end

    test "user_among/1 names the user libraries, not Media", %{publisher: publisher} do
      owner = user!(publisher)
      public = create!(owner, "public")
      private = create!(owner)

      assert Enum.sort(
               Libraries.user_among([public.uuid, private.uuid, Libraries.media_uuid(), nil])
             ) ==
               Enum.sort([public.uuid, private.uuid])
    end
  end

  describe "suspending" do
    setup %{publisher: publisher} do
      owner = user!(publisher)
      public = create!(owner, "public", "Gallery")
      %{owner: owner, public: public, shared_file: file!(owner, public.uuid)}
    end

    test "an admin takes a public library offline: it answers as private", ctx do
      admin = scope(admin!())

      assert {:ok, suspended} = Libraries.suspend_library(admin, ctx.public, "reported")

      assert Libraries.suspended?(suspended)
      refute Libraries.public?(suspended)
      refute Libraries.can?(nil, ctx.shared_file, :read)
      refute Libraries.can?(scope(user!()), ctx.shared_file, :read)
      assert Libraries.private_file?(ctx.shared_file)
      # The owner still has it, and nothing was deleted.
      assert Libraries.can?(scope(ctx.owner), ctx.shared_file, :read)
      assert Storage.get_file(ctx.shared_file.uuid)

      assert [%Entry{metadata: %{"reason" => "reported", "name" => "Gallery"}} | _] =
               entries("storage.library_suspended")
    end

    test "and brings it back", ctx do
      admin = scope(admin!())
      {:ok, suspended} = Libraries.suspend_library(admin, ctx.public)

      assert {:ok, back} = Libraries.unsuspend_library(admin, suspended)

      assert Libraries.public?(back)
      assert Libraries.can?(nil, ctx.shared_file, :read)
      refute Libraries.private_file?(ctx.shared_file)
      assert [_] = entries("storage.library_unsuspended")
    end

    test "a suspended library is excluded from nothing it was not excluded from before", ctx do
      admin = scope(admin!())
      {:ok, _} = Libraries.suspend_library(admin, ctx.public)

      refute Libraries.public?(ctx.public.uuid)
      assert Libraries.private_among([ctx.public.uuid]) == [ctx.public.uuid]
    end

    test "only an Owner or Admin may, and only for a public library", ctx do
      stranger = scope(user!())
      private = create!(ctx.owner)

      assert {:error, :not_allowed} = Libraries.suspend_library(scope(ctx.owner), ctx.public)
      assert {:error, :not_allowed} = Libraries.suspend_library(stranger, ctx.public)
      assert {:error, :not_allowed} = Libraries.suspend_library(nil, ctx.public)
      assert {:error, :not_allowed} = Libraries.suspend_library(scope(admin!()), private)
      assert {:error, :not_allowed} = Libraries.unsuspend_library(scope(admin!()), ctx.public)
      assert entries("storage.library_suspended") == []
    end
  end

  describe "the admin's list" do
    test "shows a public library as Public and offers Suspend, then Restore", %{
      publisher: publisher
    } do
      alias PhoenixKitWeb.Live.Modules.Storage.LibrariesComponent

      owner = user!(publisher)
      public = create!(owner, "public", "Open gallery")
      admin = scope(admin!())

      {:ok, socket} = LibrariesComponent.mount(%Phoenix.LiveView.Socket{})
      {:ok, socket} = LibrariesComponent.update(%{id: "libs", scope: admin, active: true}, socket)

      assert Enum.any?(socket.assigns.user_rows, &(&1.library.uuid == public.uuid))

      {:noreply, socket} =
        LibrariesComponent.handle_event(
          "suspend",
          %{"uuid" => public.uuid, "action" => "suspend"},
          socket
        )

      assert Libraries.suspended?(Libraries.get_library(public.uuid))

      {:noreply, _socket} =
        LibrariesComponent.handle_event(
          "suspend",
          %{"uuid" => public.uuid, "action" => "unsuspend"},
          socket
        )

      assert Libraries.public?(public.uuid)
    end
  end
end
