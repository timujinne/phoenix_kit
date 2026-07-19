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
  alias PhoenixKit.Users.Auth.User

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
  defp column_udt_name(table, column) do
    %{rows: [[udt_name]]} =
      Repo.query!(
        """
        SELECT udt_name
        FROM information_schema.columns
        WHERE table_name = $1 AND column_name = $2
        """,
        [table, column]
      )

    udt_name
  end

  # Returns the ON DELETE action ('a' no action, 'r' restrict, 'c' cascade,
  # 'n' set null, 'd' set default) for a named FK constraint.
  defp fk_delete_rule(constraint_name) do
    %{rows: rows} =
      Repo.query!(
        "SELECT confdeltype FROM pg_constraint WHERE conname = $1",
        [constraint_name]
      )

    case rows do
      [[rule]] -> rule
      [] -> nil
    end
  end

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

  describe "phoenix_kit_crm_lists table" do
    test "exists with the expected columns" do
      assert %{type: "uuid", nullable: "NO"} = column("phoenix_kit_crm_lists", "uuid")

      assert %{type: "character varying", nullable: "NO"} =
               column("phoenix_kit_crm_lists", "name")

      assert %{type: "character varying", nullable: "NO"} =
               column("phoenix_kit_crm_lists", "slug")

      assert %{type: "text", nullable: "YES"} =
               column("phoenix_kit_crm_lists", "description")

      assert %{type: "character varying", nullable: "NO", default: default} =
               column("phoenix_kit_crm_lists", "status")

      assert default =~ "'active'"

      assert %{type: "boolean", nullable: "NO", default: "false"} =
               column("phoenix_kit_crm_lists", "subscribable")

      assert %{type: "integer", nullable: "NO", default: "0"} =
               column("phoenix_kit_crm_lists", "subscriber_count")

      assert %{type: "character varying", nullable: "YES"} =
               column("phoenix_kit_crm_lists", "locale")

      assert %{type: "jsonb", nullable: "NO", default: default} =
               column("phoenix_kit_crm_lists", "metadata")

      assert default =~ ~r/'\{\}'::jsonb/

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_crm_lists", "inserted_at")

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_crm_lists", "updated_at")
    end

    test "status only accepts active/archived" do
      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_lists (name, slug, status) VALUES ($1, $2, $3)",
          ["Bad", "bad-status", "bogus"]
        )
      end
    end

    test "slug is unique" do
      assert index_exists?("idx_crm_lists_slug")

      Repo.query!(
        "INSERT INTO phoenix_kit_crm_lists (name, slug) VALUES ($1, $2)",
        ["Newsletter", "newsletter"]
      )

      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_lists (name, slug) VALUES ($1, $2)",
          ["Newsletter Duplicate", "newsletter"]
        )
      end
    end
  end

  describe "phoenix_kit_crm_list_members table" do
    setup do
      %{rows: [[contact_bin]]} =
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_contacts (name, email) VALUES ($1, $2) RETURNING uuid",
          ["Import Test Contact", "import.test@example.com"]
        )

      %{rows: [[list_bin]]} =
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_lists (name, slug) VALUES ($1, $2) RETURNING uuid",
          ["Members Test List", "members-test-list"]
        )

      %{contact_uuid: contact_bin, list_uuid: list_bin}
    end

    test "exists with the expected columns" do
      assert %{type: "uuid", nullable: "NO"} = column("phoenix_kit_crm_list_members", "uuid")

      assert %{type: "uuid", nullable: "NO"} =
               column("phoenix_kit_crm_list_members", "list_uuid")

      assert %{type: "uuid", nullable: "NO"} =
               column("phoenix_kit_crm_list_members", "contact_uuid")

      assert %{type: "USER-DEFINED", nullable: "YES"} =
               column("phoenix_kit_crm_list_members", "email")

      assert column_udt_name("phoenix_kit_crm_list_members", "email") == "citext"

      assert %{type: "character varying", nullable: "NO", default: status_default} =
               column("phoenix_kit_crm_list_members", "status")

      assert status_default =~ "'subscribed'"

      assert %{type: "timestamp with time zone", nullable: "YES"} =
               column("phoenix_kit_crm_list_members", "subscribed_at")

      assert %{type: "timestamp with time zone", nullable: "YES"} =
               column("phoenix_kit_crm_list_members", "unsubscribed_at")

      assert %{type: "character varying", nullable: "NO", default: source_default} =
               column("phoenix_kit_crm_list_members", "source")

      assert source_default =~ "'manual'"

      assert %{type: "jsonb", nullable: "NO", default: metadata_default} =
               column("phoenix_kit_crm_list_members", "metadata")

      assert metadata_default =~ ~r/'\{\}'::jsonb/

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_crm_list_members", "inserted_at")

      assert %{type: "timestamp with time zone", nullable: "NO"} =
               column("phoenix_kit_crm_list_members", "updated_at")
    end

    test "status only accepts subscribed/pending/removed", %{
      contact_uuid: contact_uuid,
      list_uuid: list_uuid
    } do
      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid, status) VALUES ($1, $2, $3)",
          [list_uuid, contact_uuid, "bogus"]
        )
      end
    end

    test "source only accepts manual/import/form/api", %{
      contact_uuid: contact_uuid,
      list_uuid: list_uuid
    } do
      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid, source) VALUES ($1, $2, $3)",
          [list_uuid, contact_uuid, "bogus"]
        )
      end
    end

    test "list_uuid FK cascades on delete" do
      assert fk_delete_rule("phoenix_kit_crm_list_members_list_uuid_fkey") == "c"
    end

    test "contact_uuid FK cascades on delete" do
      assert fk_delete_rule("phoenix_kit_crm_list_members_contact_uuid_fkey") == "c"
    end

    test "has a plain index on contact_uuid" do
      assert index_exists?("idx_crm_list_members_contact")
    end

    test "enforces one membership per (list_uuid, contact_uuid)", %{
      contact_uuid: contact_uuid,
      list_uuid: list_uuid
    } do
      assert index_exists?("idx_crm_list_members_list_contact")

      Repo.query!(
        "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid) VALUES ($1, $2)",
        [list_uuid, contact_uuid]
      )

      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid) VALUES ($1, $2)",
          [list_uuid, contact_uuid]
        )
      end
    end

    test "enforces unique (list_uuid, email) only among non-null emails", %{
      list_uuid: list_uuid
    } do
      assert index_exists?("idx_crm_list_members_list_email")

      %{rows: [[indexdef]]} =
        Repo.query!(
          "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_crm_list_members_list_email'"
        )

      assert indexdef =~ "UNIQUE"
      assert indexdef =~ "email IS NOT NULL"

      %{rows: [[contact_a]]} =
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_contacts (name, email) VALUES ($1, $2) RETURNING uuid",
          ["Contact A", "shared@example.com"]
        )

      %{rows: [[contact_b]]} =
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_contacts (name, email) VALUES ($1, $2) RETURNING uuid",
          ["Contact B", "other@example.com"]
        )

      Repo.query!(
        "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid, email) VALUES ($1, $2, $3)",
        [list_uuid, contact_a, "shared@example.com"]
      )

      # Same list, same email, a *different* contact — blocked by the
      # partial-unique index even though (list_uuid, contact_uuid) differs.
      assert_raise Postgrex.Error, fn ->
        Repo.query!(
          "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid, email) VALUES ($1, $2, $3)",
          [list_uuid, contact_b, "shared@example.com"]
        )
      end

      # NULL emails are unconstrained — any number of rows may have one.
      Repo.query!(
        "INSERT INTO phoenix_kit_crm_list_members (list_uuid, contact_uuid, email) VALUES ($1, $2, NULL)",
        [list_uuid, contact_b]
      )
    end
  end

  describe "phoenix_kit_crm_contacts additions" do
    test "locale is a nullable varchar(10)" do
      assert %{type: "character varying", nullable: "YES"} =
               column("phoenix_kit_crm_contacts", "locale")
    end

    test "opted_out_at is a nullable timestamptz" do
      assert %{type: "timestamp with time zone", nullable: "YES"} =
               column("phoenix_kit_crm_contacts", "opted_out_at")
    end

    test "consent is a JSONB NOT NULL default '{}'" do
      assert %{type: "jsonb", nullable: "NO", default: default} =
               column("phoenix_kit_crm_contacts", "consent")

      assert default =~ ~r/'\{\}'::jsonb/
    end
  end

  describe "phoenix_kit_newsletters_broadcasts — CRM list source" do
    test "list_uuid dropped its NOT NULL" do
      assert %{type: "uuid", nullable: "YES"} =
               column("phoenix_kit_newsletters_broadcasts", "list_uuid")
    end

    test "source_type is a NOT NULL varchar defaulting to newsletters_list" do
      assert %{type: "character varying", nullable: "NO", default: default} =
               column("phoenix_kit_newsletters_broadcasts", "source_type")

      assert default =~ "'newsletters_list'"
    end

    test "crm_list_uuid is a nullable, unconstrained uuid" do
      assert %{type: "uuid", nullable: "YES"} =
               column("phoenix_kit_newsletters_broadcasts", "crm_list_uuid")
    end

    test "has a partial index on crm_list_uuid" do
      assert index_exists?("idx_newsletters_broadcasts_crm_list")

      %{rows: [[indexdef]]} =
        Repo.query!(
          "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_newsletters_broadcasts_crm_list'"
        )

      assert indexdef =~ "crm_list_uuid IS NOT NULL"
    end
  end

  describe "phoenix_kit_newsletters_deliveries — CRM recipient source" do
    test "user_uuid dropped its NOT NULL" do
      assert %{type: "uuid", nullable: "YES"} =
               column("phoenix_kit_newsletters_deliveries", "user_uuid")
    end

    test "recipient_email is a nullable citext column" do
      assert %{type: "USER-DEFINED", nullable: "YES"} =
               column("phoenix_kit_newsletters_deliveries", "recipient_email")

      assert column_udt_name("phoenix_kit_newsletters_deliveries", "recipient_email") ==
               "citext"
    end

    defp insert_broadcast! do
      %{rows: [[uuid]]} =
        Repo.query!("""
        INSERT INTO phoenix_kit_newsletters_broadcasts (subject)
        VALUES ('V152 CHECK constraint test')
        RETURNING uuid
        """)

      uuid
    end

    test "a row with neither user_uuid nor recipient_email is rejected" do
      broadcast_uuid = insert_broadcast!()

      assert {:error, %Postgrex.Error{postgres: %{code: :check_violation}}} =
               Repo.query(
                 """
                 INSERT INTO phoenix_kit_newsletters_deliveries (broadcast_uuid, user_uuid, recipient_email)
                 VALUES ($1, NULL, NULL)
                 """,
                 [broadcast_uuid]
               )
    end

    test "a row with only recipient_email set is accepted (crm_list delivery)" do
      broadcast_uuid = insert_broadcast!()

      assert {:ok, %{num_rows: 1}} =
               Repo.query(
                 """
                 INSERT INTO phoenix_kit_newsletters_deliveries (broadcast_uuid, user_uuid, recipient_email)
                 VALUES ($1, NULL, 'crm-contact@example.com')
                 """,
                 [broadcast_uuid]
               )
    end

    test "a row with only user_uuid set is accepted (newsletters_list delivery, unchanged behavior)" do
      broadcast_uuid = insert_broadcast!()

      user =
        %User{}
        |> User.guest_user_changeset(%{
          email: "v152-check-test-#{System.unique_integer([:positive])}@example.com"
        })
        |> Repo.insert!()

      assert {:ok, %{num_rows: 1}} =
               Repo.query(
                 """
                 INSERT INTO phoenix_kit_newsletters_deliveries (broadcast_uuid, user_uuid, recipient_email)
                 VALUES ($1, $2, NULL)
                 """,
                 [broadcast_uuid, Ecto.UUID.dump!(user.uuid)]
               )
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
