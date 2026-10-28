defmodule PhoenixKit.Migrations.Postgres.V152Test do
  @moduledoc """
  Tests V152's schema state — send profiles move to core Email.

  V152.up/down can't be invoked outside an `Ecto.Migrator` runner — same
  constraint as V106Test/V107Test/V112Test/V125Test/V145Test. The schema
  is verified at boot: `test_helper.exs` runs `ensure_current/2` (now
  through V152) before any test, so these assertions pin the post-V152
  shape and a regression that drops/re-adds the wrong thing surfaces here.

  The `phoenix_kit_newsletters_send_profiles` table these assertions
  replace — and the `idx_nl_send_profiles_*` indexes — used to be pinned
  by `V145Test`; that file now only keeps the `send_profile_uuid` broadcast
  column check, since V152 drops the table V145 created.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Test.Repo

  defp column(table, column) do
    %{rows: rows} =
      Repo.query!(
        """
        SELECT data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = $1 AND column_name = $2
        """,
        [table, column]
      )

    case rows do
      [[data_type, is_nullable, default]] ->
        %{type: data_type, nullable: is_nullable, default: default}

      [] ->
        nil
    end
  end

  defp index_exists?(name) do
    %{rows: [[exists]]} =
      Repo.query!("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)", [name])

    exists
  end

  defp table_exists?(name) do
    %{rows: [[exists]]} =
      Repo.query!("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = $1)", [name])

    exists
  end

  # information_schema reports citext columns as data_type "USER-DEFINED";
  # udt_name carries the real type name.
  # Returns the ON DELETE action ('a' no action, 'r' restrict, 'c' cascade,
  # 'n' set null, 'd' set default) for a named FK constraint.
  describe "phoenix_kit_email_send_profiles table" do
    test "exists with the expected columns" do
      assert %{type: "uuid", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "uuid")

      assert %{type: "character varying", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "name")

      assert %{type: "uuid", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "integration_uuid")

      assert %{type: "character varying", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "provider_kind")

      assert %{type: "character varying", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "from_name")

      assert %{type: "character varying", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "from_email")

      assert %{type: "character varying", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "reply_to")

      assert %{type: "text", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "signature_html")

      assert %{type: "text", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "signature_text")

      assert %{type: "integer", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "rate_per_hour")

      assert %{type: "integer", nullable: "YES"} =
               column("phoenix_kit_email_send_profiles", "rate_per_day")

      assert %{type: "integer", nullable: "YES", default: "0"} =
               column("phoenix_kit_email_send_profiles", "pause_seconds")

      assert %{type: "jsonb", nullable: "NO", default: default} =
               column("phoenix_kit_email_send_profiles", "advanced")

      assert default =~ ~r/'\{\}'::jsonb/

      assert %{type: "boolean", nullable: "NO", default: "true"} =
               column("phoenix_kit_email_send_profiles", "enabled")

      assert %{type: "boolean", nullable: "NO", default: "false"} =
               column("phoenix_kit_email_send_profiles", "is_default")

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "inserted_at")

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_email_send_profiles", "updated_at")
    end

    test "has an index on integration_uuid" do
      assert index_exists?("idx_email_send_profiles_integration")
    end

    test "enforces at most one default profile via a partial unique index" do
      assert index_exists?("idx_email_send_profiles_default")

      %{rows: [[indexdef]]} =
        Repo.query!(
          "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_email_send_profiles_default'"
        )

      assert indexdef =~ "UNIQUE"
      assert indexdef =~ "is_default = true"
    end

    test "two profiles may share one integration_uuid, but a second default is rejected" do
      {:ok, integration_uuid} = Ecto.UUID.dump(Ecto.UUID.generate())

      insert = fn attrs ->
        Repo.query!(
          """
          INSERT INTO phoenix_kit_email_send_profiles
            (name, integration_uuid, provider_kind, is_default)
          VALUES ($1, $2, $3, $4)
          """,
          [attrs.name, integration_uuid, "smtp", attrs.is_default]
        )
      end

      assert insert.(%{name: "Profile A", is_default: false})
      assert insert.(%{name: "Profile B", is_default: false})
      assert insert.(%{name: "Profile C (default)", is_default: true})

      assert_raise Postgrex.Error, fn ->
        insert.(%{name: "Profile D (also default)", is_default: true})
      end
    end
  end

  describe "phoenix_kit_newsletters_send_profiles is gone" do
    test "the V145 table no longer exists" do
      refute table_exists?("phoenix_kit_newsletters_send_profiles")
    end
  end

  describe "copy semantics (mirrors V152.up's INSERT...SELECT)" do
    # V152.up can't be re-run against a populated V145 table in this test
    # suite — the full chain always starts from a fresh V1 install with
    # nothing in `phoenix_kit_newsletters_send_profiles` for it to copy
    # (see PrefixMigrationTest moduledoc). This test stands in a scratch
    # table shaped like the old table and runs the *same* explicit
    # column-list copy the migration uses, to pin that every column
    # (uuid included) survives the move rather than only some of them.
    test "copies every column, including the uuid, across unchanged" do
      Repo.query!("""
      CREATE TEMP TABLE staged_newsletters_send_profiles (
        uuid UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        integration_uuid UUID NOT NULL,
        provider_kind VARCHAR(40) NOT NULL,
        from_name VARCHAR(255), from_email VARCHAR(255), reply_to VARCHAR(255),
        signature_html TEXT, signature_text TEXT,
        rate_per_hour INTEGER, rate_per_day INTEGER, pause_seconds INTEGER DEFAULT 0,
        advanced JSONB NOT NULL DEFAULT '{}'::jsonb,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        is_default BOOLEAN NOT NULL DEFAULT FALSE,
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
      """)

      uuid = Ecto.UUID.generate()
      {:ok, uuid_bin} = Ecto.UUID.dump(uuid)
      {:ok, integration_uuid} = Ecto.UUID.dump(Ecto.UUID.generate())

      Repo.query!(
        """
        INSERT INTO staged_newsletters_send_profiles
          (uuid, name, integration_uuid, provider_kind, from_name, rate_per_hour)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        [uuid_bin, "Marketing", integration_uuid, "smtp", "Hydroforce", 100]
      )

      columns = """
      uuid, name, integration_uuid, provider_kind, from_name, from_email, reply_to,
      signature_html, signature_text, rate_per_hour, rate_per_day, pause_seconds,
      advanced, enabled, is_default, inserted_at, updated_at
      """

      Repo.query!("""
      INSERT INTO phoenix_kit_email_send_profiles (#{columns})
      SELECT #{columns} FROM staged_newsletters_send_profiles
      ON CONFLICT (uuid) DO NOTHING
      """)

      %{rows: [[name, ^integration_uuid, provider_kind, from_name, rate_per_hour]]} =
        Repo.query!(
          """
          SELECT name, integration_uuid, provider_kind, from_name, rate_per_hour
          FROM phoenix_kit_email_send_profiles WHERE uuid = $1
          """,
          [uuid_bin]
        )

      assert name == "Marketing"
      assert provider_kind == "smtp"
      assert from_name == "Hydroforce"
      assert rate_per_hour == 100
    end

    test "a uuid already present in the target is left alone (ON CONFLICT DO NOTHING)" do
      {:ok, integration_uuid} = Ecto.UUID.dump(Ecto.UUID.generate())

      %{rows: [[uuid_bin]]} =
        Repo.query!(
          """
          INSERT INTO phoenix_kit_email_send_profiles (name, integration_uuid, provider_kind)
          VALUES ($1, $2, $3)
          RETURNING uuid
          """,
          ["Original", integration_uuid, "smtp"]
        )

      Repo.query!("""
      CREATE TEMP TABLE staged_dupe (
        uuid UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        integration_uuid UUID NOT NULL,
        provider_kind VARCHAR(40) NOT NULL
      )
      """)

      Repo.query!(
        "INSERT INTO staged_dupe (uuid, name, integration_uuid, provider_kind) VALUES ($1, $2, $3, $4)",
        [uuid_bin, "Would-be duplicate", integration_uuid, "smtp"]
      )

      Repo.query!("""
      INSERT INTO phoenix_kit_email_send_profiles (uuid, name, integration_uuid, provider_kind)
      SELECT uuid, name, integration_uuid, provider_kind FROM staged_dupe
      ON CONFLICT (uuid) DO NOTHING
      """)

      %{rows: [[name]]} =
        Repo.query!("SELECT name FROM phoenix_kit_email_send_profiles WHERE uuid = $1", [
          uuid_bin
        ])

      assert name == "Original"
    end
  end

  describe "version marker" do
    test "phoenix_kit table comment is at or past V152" do
      %{rows: [[comment]]} =
        Repo.query!("SELECT obj_description('phoenix_kit'::regclass, 'pg_class')")

      # >= rather than ==: pinning the exact latest version breaks this
      # test every time a NEWER migration ships.
      assert String.to_integer(comment) >= 152
    end
  end
end
