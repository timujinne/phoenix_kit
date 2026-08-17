defmodule PhoenixKit.Migrations.Postgres.V174Test do
  @moduledoc """
  V174's data repair, run against seeded misclassified rows.

  V174.up/1 can't be invoked outside an `Ecto.Migrator` runner (same
  constraint as V164Test and friends), and by the time any test runs the
  chain has already been applied — to empty tables, proving nothing. So the
  migration exposes its statements via `repair_statements/1` (up/1 executes
  exactly that list), and this suite runs the REAL SQL against rows shaped
  like the corruption found in the wild: `.mov`/`.mp3` uploads stored with
  `file_type: "image"` by a caller that hardcoded it, and mp3s whose mime
  the old extension map could only answer `application/octet-stream` for.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Migrations.Postgres.V174
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  defp run_repair do
    Enum.map(V174.repair_statements("public."), &Repo.query!(&1))
  end

  # Schemaless insert_all speaks the driver's types, so uuids stay 16-byte
  # binaries throughout — helpers return them raw and the SELECT helpers pass
  # them straight back as parameters.
  defp owner_uuid do
    {:ok, user} =
      Auth.register_user(%{
        email: "v174-#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    Ecto.UUID.dump!(user.uuid)
  end

  defp insert_file!(attrs) do
    now = DateTime.utc_now()
    unique = System.unique_integer([:positive])

    base = %{
      original_file_name: "file-#{unique}",
      file_name: "file-#{unique}",
      mime_type: "application/octet-stream",
      file_type: "other",
      ext: "bin",
      file_checksum: "checksum-#{unique}",
      user_file_checksum: "user-checksum-#{unique}",
      size: 123,
      # The user_or_parent_check constraint: every non-variant row has an owner.
      user_uuid: owner_uuid(),
      inserted_at: now,
      updated_at: now
    }

    {1, [%{uuid: uuid}]} =
      Repo.insert_all("phoenix_kit_files", [Map.merge(base, attrs)], returning: [:uuid])

    uuid
  end

  defp insert_instance!(file_uuid, attrs) do
    now = DateTime.utc_now()
    unique = System.unique_integer([:positive])

    base = %{
      variant_name: "original",
      file_name: "instance-#{unique}",
      mime_type: "application/octet-stream",
      ext: "bin",
      checksum: "checksum-#{unique}",
      size: 123,
      file_uuid: file_uuid,
      inserted_at: now,
      updated_at: now
    }

    {1, [%{uuid: uuid}]} =
      Repo.insert_all("phoenix_kit_file_instances", [Map.merge(base, attrs)], returning: [:uuid])

    uuid
  end

  defp file_row(uuid) do
    %{rows: [[mime, type]]} =
      Repo.query!(
        "SELECT mime_type, file_type FROM phoenix_kit_files WHERE uuid = $1",
        [uuid]
      )

    {mime, type}
  end

  defp instance_mime(uuid) do
    %{rows: [[mime]]} =
      Repo.query!(
        "SELECT mime_type FROM phoenix_kit_file_instances WHERE uuid = $1",
        [uuid]
      )

    mime
  end

  describe "repair_statements/1" do
    test "a video stored as 'image' is reclassified from its mime" do
      uuid =
        insert_file!(%{
          original_file_name: "clip.mov",
          mime_type: "video/quicktime",
          file_type: "image",
          ext: "mov"
        })

      run_repair()

      assert file_row(uuid) == {"video/quicktime", "video"}
    end

    test "an mp3 with an octet-stream mime gets both mime and type back" do
      # The two defects compounding: the caller claimed "image" AND the old
      # extension map knew no audio type. The mime repair must run first so
      # the reclassification sees audio/mpeg in the same pass.
      uuid =
        insert_file!(%{
          original_file_name: "song.mp3",
          mime_type: "application/octet-stream",
          file_type: "image",
          ext: "mp3"
        })

      run_repair()

      assert file_row(uuid) == {"audio/mpeg", "audio"}
    end

    test "instance rows are repaired too, dotted extension included" do
      # file_controller serves with the INSTANCE's mime — this octet-stream is
      # the one a browser's <audio> tag actually saw. Callers never agreed on
      # the leading dot, so both forms must repair.
      # (file_uuid, variant_name) is unique, so the dotted twin rides a
      # different variant slot.
      file_uuid = insert_file!(%{mime_type: "audio/mp4", file_type: "audio", ext: "m4a"})
      bare = insert_instance!(file_uuid, %{ext: "m4a"})
      dotted = insert_instance!(file_uuid, %{ext: ".m4a", variant_name: "thumbnail"})

      run_repair()

      assert instance_mime(bare) == "audio/mp4"
      assert instance_mime(dotted) == "audio/mp4"
    end

    test "system types and evidence-free rows are left alone" do
      # "tile" was chosen by internal machinery — mime evidence saying
      # "image" is exactly what a tile looks like and must not reclassify it.
      tile =
        insert_file!(%{mime_type: "image/png", file_type: "tile", ext: "png"})

      # Unknown mime carries no verdict; the claim may know more.
      unknown =
        insert_file!(%{mime_type: "application/x-thing", file_type: "document", ext: "xyz"})

      healthy =
        insert_file!(%{mime_type: "image/png", file_type: "image", ext: "png"})

      run_repair()

      assert file_row(tile) == {"image/png", "tile"}
      assert file_row(unknown) == {"application/x-thing", "document"}
      assert file_row(healthy) == {"image/png", "image"}
    end

    test "the repair is idempotent" do
      insert_file!(%{
        original_file_name: "song.mp3",
        mime_type: "application/octet-stream",
        file_type: "image",
        ext: "mp3"
      })

      first = run_repair()
      assert Enum.any?(first, &(&1.num_rows > 0))

      # A second pass finds nothing left to correct — the WHERE clauses
      # exclude already-repaired rows, so re-running (multi-step upgrade
      # replays, repair tooling) rewrites nothing.
      second = run_repair()
      assert Enum.all?(second, &(&1.num_rows == 0))
    end
  end
end
