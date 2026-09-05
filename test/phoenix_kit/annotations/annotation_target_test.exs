defmodule PhoenixKit.Annotations.AnnotationTargetTest do
  @moduledoc """
  V183: an annotation anchors to a target — a file (the pre-V183 shape,
  `file_uuid` filled in both columns) or anything else (a projects
  whiteboard, say) with no file at all. The schema mirrors the DB CHECK
  so a bad shape is a changeset error, and the Etcher adapter accepts
  both targets.
  """

  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Annotations
  alias PhoenixKit.Annotations.Annotation
  alias PhoenixKit.Modules.Storage.EtcherAdapter
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Users.Auth

  @geometry %{"path" => [[0, 0], [10, 10]]}

  describe "the schema" do
    test "a file uuid alone is a file target (every pre-V183 caller)" do
      file = UUIDv7.generate()

      cs =
        Annotation.changeset(%Annotation{}, %{file_uuid: file, kind: "line", geometry: @geometry})

      assert cs.valid?
      assert Ecto.Changeset.get_field(cs, :target_type) == "file"
      assert Ecto.Changeset.get_field(cs, :target_uuid) == file
    end

    test "another target carries no file" do
      cs =
        Annotation.changeset(%Annotation{}, %{
          target_type: "projects_whiteboard",
          target_uuid: UUIDv7.generate(),
          kind: "freehand",
          geometry: @geometry
        })

      assert cs.valid?
      assert Ecto.Changeset.get_field(cs, :file_uuid) == nil
    end

    test "the two shapes are pinned" do
      # a file target whose file disagrees with the target
      cs =
        Annotation.changeset(%Annotation{}, %{
          target_type: "file",
          target_uuid: UUIDv7.generate(),
          file_uuid: UUIDv7.generate(),
          kind: "line",
          geometry: @geometry
        })

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :file_uuid)

      # a non-file target smuggling a file
      cs =
        Annotation.changeset(%Annotation{}, %{
          target_type: "projects_whiteboard",
          target_uuid: UUIDv7.generate(),
          file_uuid: UUIDv7.generate(),
          kind: "line",
          geometry: @geometry
        })

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :file_uuid)

      # no target at all
      cs = Annotation.changeset(%Annotation{}, %{kind: "line", geometry: @geometry})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :target_uuid)
    end

    test "the adapter never takes the target from the payload" do
      refute :target_type in Annotation.adapter_writable_fields()
      refute :target_uuid in Annotation.adapter_writable_fields()
      refute :file_uuid in Annotation.adapter_writable_fields()
    end
  end

  describe "target_type shape is enforced on the changeset, not only the adapter" do
    # The guard used to live only in `EtcherAdapter`, which is not the sole
    # writer: `Annotations.create/1` is public and is the path a board takes.
    # Without it on the changeset, an over-long type reached
    # `character varying(32)` and came back as a raw Postgres error.

    test "a type longer than the column is a changeset error, not a DB error" do
      attrs = %{
        target_type: String.duplicate("b", 33),
        target_uuid: UUIDv7.generate(),
        kind: "line",
        geometry: @geometry
      }

      assert {:error, changeset} = Annotations.create(attrs)
      assert %{target_type: [_ | _]} = errors_on(changeset)
    end

    test "a type with characters the column would take but the domain should not" do
      # `""` is deliberately absent: Ecto's `cast/3` treats an empty string as
      # nil, so the field falls back to the schema default "file" and the
      # failure lands on `validate_target/1` instead — a different path, and
      # one the neighbouring describe block already covers.
      for bad <- ["Board", "board-1", "board space", "1board", String.duplicate("b", 40)] do
        attrs = %{
          target_type: bad,
          target_uuid: UUIDv7.generate(),
          kind: "line",
          geometry: @geometry
        }

        assert {:error, changeset} = Annotations.create(attrs),
               "expected #{inspect(bad)} to be refused"

        assert Map.has_key?(errors_on(changeset), :target_type)
      end
    end

    test "a well-formed non-file type still saves" do
      attrs = %{
        target_type: "projects_board",
        target_uuid: UUIDv7.generate(),
        kind: "line",
        geometry: @geometry
      }

      assert {:ok, annotation} = Annotations.create(attrs)
      assert annotation.target_type == "projects_board"
      assert is_nil(annotation.file_uuid)
    end

    test "the adapter and the schema share one regex" do
      # Two copies would drift, and the adapter's early rejection has to agree
      # with what the changeset would have said.
      assert Regex.match?(Annotation.target_type_format(), "projects_board")
      refute Regex.match?(Annotation.target_type_format(), String.duplicate("b", 33))
    end
  end

  describe "the DB" do
    test "V183 columns and the target CHECK are in place" do
      %{rows: rows} =
        Repo.query!(
          "SELECT column_name, is_nullable FROM information_schema.columns WHERE table_name = 'phoenix_kit_annotations' AND column_name IN ('file_uuid', 'target_type', 'target_uuid')"
        )

      assert Enum.sort(rows) == [
               ["file_uuid", "YES"],
               ["target_type", "NO"],
               ["target_uuid", "YES"]
             ]

      %{rows: [[def]]} =
        Repo.query!(
          "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'phoenix_kit_annotations_target_check'"
        )

      assert def =~ "target_type"
    end

    test "a non-file annotation round-trips through the context and the adapter" do
      board = UUIDv7.generate()

      {:ok, a} =
        EtcherAdapter.create(%{
          "target_type" => "projects_whiteboard",
          "target_uuid" => board,
          "kind" => "rectangle",
          "geometry" => @geometry,
          # anything not on the schema whitelist is dropped, not fatal
          "anchor_x" => 12
        })

      assert a.file_uuid == nil
      assert a.target_type == "projects_whiteboard"
      assert a.target_uuid == board

      assert [%Annotation{uuid: uuid}] = Annotations.list_for_target("projects_whiteboard", board)
      assert uuid == a.uuid
      assert [_] = EtcherAdapter.list_for("projects_whiteboard", board)
      assert EtcherAdapter.list_for("projects_whiteboard", UUIDv7.generate()) == []

      {:ok, _} = EtcherAdapter.update(a.uuid, %{"title" => "Island"})
      assert Annotations.get(a.uuid).title == "Island"
      :ok = EtcherAdapter.delete(a.uuid)
      assert Annotations.list_for_target("projects_whiteboard", board) == []
    end

    test "a FILE target through the adapter — the pre-V183 production path — sets both columns" do
      # The sweep (2026-09-05): every drawing on a photo goes this way, and
      # nothing crossed the rewritten create/1 with a "file" target.
      file = file_fixture!()

      {:ok, a} =
        EtcherAdapter.create(%{
          "target_type" => "file",
          "target_uuid" => file.uuid,
          "kind" => "rectangle",
          "geometry" => @geometry
        })

      assert a.file_uuid == file.uuid
      assert a.target_type == "file"
      assert a.target_uuid == file.uuid

      # Both the old and the new read paths find it.
      assert [%Annotation{uuid: uuid}] = Annotations.list_for_file(file.uuid)
      assert uuid == a.uuid
      assert [%Annotation{uuid: ^uuid}] = EtcherAdapter.list_for("file", file.uuid)
      assert [%Annotation{uuid: ^uuid}] = Annotations.list_for_target("file", file.uuid)
      assert Annotations.has_annotations?(file.uuid)
    end

    test "delete_for_target clears a board's shapes and never touches files" do
      board = UUIDv7.generate()

      for kind <- ~w(line marker) do
        {:ok, _} =
          Annotations.create(%{
            target_type: "projects_whiteboard",
            target_uuid: board,
            kind: kind,
            geometry: @geometry
          })
      end

      assert Annotations.delete_for_target("projects_whiteboard", board) == 2
      assert Annotations.list_for_target("projects_whiteboard", board) == []
      assert Annotations.delete_for_target("file", UUIDv7.generate()) == 0
    end

    test "the adapter refuses a malformed target type" do
      assert {:error, :unsupported_target} =
               EtcherAdapter.create(%{
                 "target_type" => "Drop Table;",
                 "target_uuid" => UUIDv7.generate(),
                 "kind" => "line",
                 "geometry" => @geometry
               })
    end
  end

  defp file_fixture! do
    n = System.unique_integer([:positive])

    {:ok, user} =
      Auth.register_user(%{email: "target-#{n}@example.com", password: "ValidPassword123!"})

    {:ok, file} =
      Repo.insert(%StorageFile{
        original_file_name: "target_#{n}.jpg",
        file_name: "target_#{n}.jpg",
        mime_type: "image/jpeg",
        file_type: "image",
        ext: "jpg",
        file_checksum: "sha256:target-#{n}",
        user_file_checksum: "user-sha256:target-#{n}",
        size: 1024,
        status: "active",
        user_uuid: user.uuid
      })

    file
  end
end
