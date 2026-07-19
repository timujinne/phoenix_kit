defmodule PhoenixKit.Migrations.Postgres.V152 do
  @moduledoc """
  V152: Newsletters/CRM/Core restructuring — accumulator migration.

  Per the "one open migration" rule: while V152 is unreleased, every DDL
  step of the restructuring plan lands here as its own section rather than
  opening a new vNNN. Add new work as another `up_*`/`down_*` pair, called
  from `up/1`/`down/1` in application order (`down/1` unwinds in reverse).
  Keep each section's DDL self-contained and idempotent, same as any other
  migration in this chain.

  > #### The accumulator's one sharp edge — read before appending {: .warning}
  >
  > The chain tracks progress by a **single version comment** on the
  > `phoenix_kit` table. A database that has already stamped `'152'` will
  > **never re-enter this module**, so a section appended *after* that
  > stamp silently never applies there. Two hard consequences:
  >
  > 1. **The moment V152 ships in a release, it is CLOSED.** The next DDL
  >    opens V153 — the one-open-migration rule applies only to the
  >    unreleased window. Appending to a released version would strand
  >    every already-migrated host with missing DDL and no error.
  > 2. **Dev/staging databases running this branch must re-apply after
  >    every appended section**: `mix ecto.rollback --step 1` (the file
  >    migration downs the whole version — data written by earlier
  >    sections survives via their own down/up copy cycles), then
  >    `mix phoenix_kit.update` to run the version again with all
  >    sections. Skipping this dance leaves the stamp at `'152'` with
  >    only the older sections applied — the exact silent-skip failure
  >    this warning exists to prevent.

  ## Section: send profiles move to core Email

  Creates `phoenix_kit_email_send_profiles` — the same shape V145 gave
  `phoenix_kit_newsletters_send_profiles`, now owned by core's
  `PhoenixKit.Email` namespace instead of the newsletters module (send
  profiles stop being newsletters-only, so any module can resolve one).
  Every row is copied across by its existing `uuid` (the PK on both
  tables, so nothing is renumbered) and the V145 table is then dropped.
  `idx_nl_send_profiles_integration`/`idx_nl_send_profiles_default` become
  `idx_email_send_profiles_integration`/`idx_email_send_profiles_default`.

  Does **not** touch `phoenix_kit_newsletters_broadcasts.send_profile_uuid`
  (added by V145) — it was already a bare UUID with no FK, so it still
  points at the same row regardless of which table now owns it.

  The copy+drop only runs when the V145 table is still present, so `up/1`
  is safe to re-run after it has already completed once (nothing left to
  copy, no "relation does not exist" on the second pass). Same for `down/1`
  against the V152 table.

  ## Section: CRM contact lists

  Two new tables plus three columns on the existing V138
  `phoenix_kit_crm_contacts`, for Stage 3 of the restructuring plan
  (list-based sending + account import):

    * `phoenix_kit_crm_lists` — a named, sluggable list (`status`
      active/archived, `subscribable` pre-provisioned for the Stage-4
      preference center, `subscriber_count` a maintained cache, `locale`
      a nullable content-language tag the admin UI can bulk-apply to the
      list's contacts).
    * `phoenix_kit_crm_list_members` — the list↔contact join, carrying a
      denormalized `email` snapshot taken at add-time (so a list survives
      a later change to the contact's own email) and its own `status`
      (subscribed/pending/removed) and `source` (manual/import/form/api).
      `UNIQUE (list_uuid, contact_uuid)` keeps one membership row per
      contact per list; `UNIQUE (list_uuid, email) WHERE email IS NOT
      NULL` (`idx_crm_list_members_list_email`) is the actual per-list
      email uniqueness guard — a `removed` member still holds its email
      slot, so re-importing the same address cannot silently create a
      second, resubscribed row under it.
    * `phoenix_kit_crm_contacts.locale` / `.opted_out_at` / `.consent` —
      opt-out and consent live on the contact (not the membership), so
      an opt-out applies across every list the contact belongs to; the
      Stage-4 send path checks membership `subscribed` AND contact not
      opted out.

  citext (already ensured by V151) backs `email` here too, for the same
  case-insensitive matching. All operations are idempotent.

  ## Section: broadcasts can source recipients from a CRM list

  Minimal Stage-4 groundwork: a broadcast can now target either its own
  `phoenix_kit_newsletters_lists` list (unchanged default behavior) or a
  `phoenix_kit_crm_lists` list, tagged by the new `source_type` column
  (`'newsletters_list'` default / `'crm_list'`) — validated at the Ecto
  layer only, same as `broadcasts.status` already is (no DB CHECK on
  either). `crm_list_uuid` is a bare UUID with no FK, matching
  `send_profile_uuid`'s existing soft-reference pattern: newsletters must
  not hard-depend on the CRM module being installed.

  `broadcasts.list_uuid` and `deliveries.user_uuid` both drop their `NOT
  NULL` — a `crm_list` broadcast has no newsletters list, and a
  CRM-sourced delivery generally has no core `User` row at all (most CRM
  contacts never log in). `deliveries.recipient_email` is the new
  column that makes such a delivery addressable: a CITEXT snapshot of the
  recipient's email taken when the send is enqueued, mirroring how
  `phoenix_kit_crm_list_members.email` already snapshots at add-time.

  `down/1` deliberately does **not** restore the two `NOT NULL`s — by the
  time this ships, a dev database exercising this feature will have rows
  with `list_uuid`/`user_uuid` NULL, and re-imposing the constraint would
  make the documented rollback-and-reapply dance (see the warning above)
  fail on exactly the data this section exists to create. Only the new
  columns are dropped.

  A dropped `user_uuid` `NOT NULL` alone would let a delivery row be
  addressable by neither identifier at all — `phoenix_kit_newsletters_deliveries_recipient_check`
  (`CHECK (user_uuid IS NOT NULL OR recipient_email IS NOT NULL)`) closes
  that gap; `down/1` drops it along with the columns. The Ecto-layer
  `Broadcaster` insert path already guards the same invariant before this
  constraint existed — this is a cheap, redundant DB-level backstop, not
  a replacement for it.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.Helpers

  @send_profile_columns """
  uuid, name, integration_uuid, provider_kind, from_name, from_email, reply_to,
  signature_html, signature_text, rate_per_hour, rate_per_day, pause_seconds,
  advanced, enabled, is_default, inserted_at, updated_at
  """

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    up_send_profiles_to_core_email(opts, prefix, p)
    up_crm_contact_lists(opts, prefix, p)
    up_broadcast_crm_source(opts, prefix, p)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '152'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Reverse of up/1: added third, so it unwinds first.
    down_broadcast_crm_source(opts, prefix, p)
    # CRM contact lists was added second, so it unwinds next.
    down_crm_contact_lists(opts, prefix, p)
    down_send_profiles_to_core_email(opts, prefix, p)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '151'")
  end

  # ── Section: send profiles move to core Email ──

  defp up_send_profiles_to_core_email(opts, prefix, p) do
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_email_send_profiles (
      uuid UUID PRIMARY KEY DEFAULT #{Helpers.uuid_v7_call(prefix)},
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

    execute("""
    CREATE INDEX IF NOT EXISTS idx_email_send_profiles_integration
    ON #{p}phoenix_kit_email_send_profiles(integration_uuid)
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_email_send_profiles_default
    ON #{p}phoenix_kit_email_send_profiles(is_default) WHERE is_default = TRUE
    """)

    if table_exists?(opts, prefix, "phoenix_kit_newsletters_send_profiles") do
      execute("""
      INSERT INTO #{p}phoenix_kit_email_send_profiles (#{@send_profile_columns})
      SELECT #{@send_profile_columns} FROM #{p}phoenix_kit_newsletters_send_profiles
      ON CONFLICT (uuid) DO NOTHING
      """)

      execute("DROP TABLE IF EXISTS #{p}phoenix_kit_newsletters_send_profiles CASCADE")
    end
  end

  defp down_send_profiles_to_core_email(opts, prefix, p) do
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_newsletters_send_profiles (
      uuid UUID PRIMARY KEY DEFAULT #{Helpers.uuid_v7_call(prefix)},
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

    execute("""
    CREATE INDEX IF NOT EXISTS idx_nl_send_profiles_integration
    ON #{p}phoenix_kit_newsletters_send_profiles(integration_uuid)
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_nl_send_profiles_default
    ON #{p}phoenix_kit_newsletters_send_profiles(is_default) WHERE is_default = TRUE
    """)

    if table_exists?(opts, prefix, "phoenix_kit_email_send_profiles") do
      execute("""
      INSERT INTO #{p}phoenix_kit_newsletters_send_profiles (#{@send_profile_columns})
      SELECT #{@send_profile_columns} FROM #{p}phoenix_kit_email_send_profiles
      ON CONFLICT (uuid) DO NOTHING
      """)

      execute("DROP TABLE IF EXISTS #{p}phoenix_kit_email_send_profiles CASCADE")
    end
  end

  # ── Section: CRM contact lists ──

  defp up_crm_contact_lists(_opts, prefix, p) do
    Helpers.ensure_extension!("citext")

    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_crm_lists (
      uuid UUID PRIMARY KEY DEFAULT #{Helpers.uuid_v7_call(prefix)},
      name VARCHAR(255) NOT NULL,
      slug VARCHAR(255) NOT NULL,
      description TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'archived')),
      subscribable BOOLEAN NOT NULL DEFAULT FALSE,
      subscriber_count INTEGER NOT NULL DEFAULT 0,
      locale VARCHAR(10),
      metadata JSONB NOT NULL DEFAULT '{}',
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_crm_lists_slug
    ON #{p}phoenix_kit_crm_lists (slug)
    """)

    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_crm_list_members (
      uuid UUID PRIMARY KEY DEFAULT #{Helpers.uuid_v7_call(prefix)},
      list_uuid UUID NOT NULL REFERENCES #{p}phoenix_kit_crm_lists(uuid) ON DELETE CASCADE,
      contact_uuid UUID NOT NULL REFERENCES #{p}phoenix_kit_crm_contacts(uuid) ON DELETE CASCADE,
      email CITEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'subscribed'
        CHECK (status IN ('subscribed', 'pending', 'removed')),
      subscribed_at TIMESTAMPTZ,
      unsubscribed_at TIMESTAMPTZ,
      source VARCHAR(20) NOT NULL DEFAULT 'manual'
        CHECK (source IN ('manual', 'import', 'form', 'api')),
      metadata JSONB NOT NULL DEFAULT '{}',
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_crm_list_members_list_contact
    ON #{p}phoenix_kit_crm_list_members (list_uuid, contact_uuid)
    """)

    # Per-list email uniqueness on the denormalized snapshot — a `removed`
    # member still holds its email slot, so re-importing the same address
    # cannot silently resubscribe it under a second row.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_crm_list_members_list_email
    ON #{p}phoenix_kit_crm_list_members (list_uuid, email)
    WHERE email IS NOT NULL
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS idx_crm_list_members_contact
    ON #{p}phoenix_kit_crm_list_members (contact_uuid)
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_crm_contacts
    ADD COLUMN IF NOT EXISTS locale VARCHAR(10)
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_crm_contacts
    ADD COLUMN IF NOT EXISTS opted_out_at TIMESTAMPTZ
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_crm_contacts
    ADD COLUMN IF NOT EXISTS consent JSONB NOT NULL DEFAULT '{}'
    """)
  end

  defp down_crm_contact_lists(_opts, _prefix, p) do
    execute("ALTER TABLE #{p}phoenix_kit_crm_contacts DROP COLUMN IF EXISTS consent")
    execute("ALTER TABLE #{p}phoenix_kit_crm_contacts DROP COLUMN IF EXISTS opted_out_at")
    execute("ALTER TABLE #{p}phoenix_kit_crm_contacts DROP COLUMN IF EXISTS locale")

    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_crm_list_members CASCADE")
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_crm_lists CASCADE")
  end

  # ── Section: broadcasts can source recipients from a CRM list ──

  defp up_broadcast_crm_source(opts, prefix, p) do
    Helpers.ensure_extension!("citext")

    # A crm_list broadcast has no newsletters list of its own.
    execute("""
    ALTER TABLE #{p}phoenix_kit_newsletters_broadcasts
    ALTER COLUMN list_uuid DROP NOT NULL
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_newsletters_broadcasts
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(20) NOT NULL DEFAULT 'newsletters_list'
    """)

    # Bare UUID, no FK — same soft-reference pattern as send_profile_uuid:
    # newsletters must not hard-depend on the CRM module being installed.
    execute("""
    ALTER TABLE #{p}phoenix_kit_newsletters_broadcasts
    ADD COLUMN IF NOT EXISTS crm_list_uuid UUID
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS idx_newsletters_broadcasts_crm_list
    ON #{p}phoenix_kit_newsletters_broadcasts (crm_list_uuid)
    WHERE crm_list_uuid IS NOT NULL
    """)

    # A CRM-sourced delivery generally has no core User row at all (most
    # CRM contacts never log in) — recipient_email is the address that
    # makes such a delivery addressable, snapshotted when the send is
    # enqueued (same idea as phoenix_kit_crm_list_members.email).
    execute("""
    ALTER TABLE #{p}phoenix_kit_newsletters_deliveries
    ALTER COLUMN user_uuid DROP NOT NULL
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_newsletters_deliveries
    ADD COLUMN IF NOT EXISTS recipient_email CITEXT
    """)

    # Cheap integrity guard: with both NOT NULLs dropped above, a delivery
    # row addressable by neither a core User nor a snapshotted email is
    # unreachable by any send path — Postgres has no
    # `ADD CONSTRAINT IF NOT EXISTS`, so guard on the constraint name (same
    # pattern used elsewhere in this migration chain, e.g. V125's
    # `add_status_entity_uuid_fk/2`). Deliberately no CHECK on `source_type`
    # here — this repo's convention keeps enum-shaped columns Ecto-only
    # (see `broadcasts.status`), not DB CHECK-constrained.
    escaped_prefix = Map.get(opts, :escaped_prefix, prefix)

    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT FROM information_schema.table_constraints
        WHERE table_schema = '#{escaped_prefix}'
          AND table_name = 'phoenix_kit_newsletters_deliveries'
          AND constraint_name = 'phoenix_kit_newsletters_deliveries_recipient_check'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_newsletters_deliveries
          ADD CONSTRAINT phoenix_kit_newsletters_deliveries_recipient_check
          CHECK (user_uuid IS NOT NULL OR recipient_email IS NOT NULL);
      END IF;
    END $$;
    """)
  end

  defp down_broadcast_crm_source(_opts, _prefix, p) do
    # Deliberately does NOT restore the NOT NULLs — see the module doc's
    # "Section: broadcasts can source recipients from a CRM list" note.
    execute(
      "ALTER TABLE #{p}phoenix_kit_newsletters_deliveries DROP CONSTRAINT IF EXISTS phoenix_kit_newsletters_deliveries_recipient_check"
    )

    execute("DROP INDEX IF EXISTS #{p}idx_newsletters_broadcasts_crm_list")

    execute(
      "ALTER TABLE #{p}phoenix_kit_newsletters_broadcasts DROP COLUMN IF EXISTS crm_list_uuid"
    )

    execute(
      "ALTER TABLE #{p}phoenix_kit_newsletters_broadcasts DROP COLUMN IF EXISTS source_type"
    )

    execute(
      "ALTER TABLE #{p}phoenix_kit_newsletters_deliveries DROP COLUMN IF EXISTS recipient_email"
    )
  end

  # ── Shared helpers ──

  defp table_exists?(opts, prefix, table_name) do
    escaped_prefix = Map.get(opts, :escaped_prefix, prefix)

    case repo().query(
           """
           SELECT EXISTS (
             SELECT FROM information_schema.tables
             WHERE table_name = '#{table_name}'
             AND table_schema = '#{escaped_prefix}'
           )
           """,
           [],
           log: false
         ) do
      {:ok, %{rows: [[true]]}} -> true
      _ -> false
    end
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
