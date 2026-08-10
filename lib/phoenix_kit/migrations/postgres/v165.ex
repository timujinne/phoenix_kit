defmodule PhoenixKit.Migrations.Postgres.V165 do
  @moduledoc """
  V165: cross-module mentions and access requests.

  ## `phoenix_kit_mentions`

  The reverse index for `@`/`#` mentions. The canonical mention lives in the
  text itself as a token, which is what survives copy-paste, edit history,
  no-JS reading and a module being uninstalled. This table answers the
  question the text cannot: **what links here** — and gives notification
  fan-out something to diff against without re-scanning every body.

  It is a CACHE of the current head of each field, rebuilt from the tokens
  on every durable save. It is deliberately not versioned: history lives in
  the text.

  No foreign key on `target_uuid`: it points into ~28 optional packages'
  tables, most of which may not be installed. The source side is the same —
  a comment, a task description, a note. Orphans are expected and handled at
  read time, where a target that no longer resolves renders as plain text
  rather than a link.

  ## `phoenix_kit_access_requests`

  When a mention points at something the reader cannot open, the reader is
  told it exists but not what it is — and can ask for access. That request
  needs somewhere to live so the owner can act on it and so the same person
  cannot spam the same record.

  `status` is a string sentinel (`pending` / `granted` / `denied` /
  `cancelled`), matching the workspace's soft-delete convention rather than
  a boolean pair.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.Helpers

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    Helpers.ensure_uuid_v7_function(prefix)
    uuid_default = Helpers.uuid_v7_call(prefix)

    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_mentions (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      -- What CONTAINS the mention. Free-form type + uuid for the same
      -- reason the target is: the container may be any module's record.
      source_type TEXT NOT NULL,
      source_uuid UUID NOT NULL,
      -- Which field of that record. A task with a description AND a
      -- summary needs two independent sets of mentions, and re-saving one
      -- must not wipe the other's rows.
      source_field TEXT NOT NULL DEFAULT 'body',
      -- What is MENTIONED. `kind` distinguishes an @ping from a # link so
      -- notification fan-out doesn't have to special-case the type name.
      kind TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_uuid UUID NOT NULL,
      -- The label the author saw when they picked. Kept so "what links
      -- here" can render without resolving, and so a deleted target still
      -- has a human name in the reverse index.
      label TEXT,
      actor_uuid UUID REFERENCES #{p}phoenix_kit_users(uuid) ON DELETE SET NULL,
      -- Set once the @ping has been delivered, so re-saving the same text
      -- never notifies twice. NULL for # links, which don't notify.
      notified_at TIMESTAMPTZ,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT phoenix_kit_mentions_kind_check CHECK (kind IN ('user', 'resource'))
    )
    """)

    # One row per (source field, target). Mentioning the same person twice in
    # one comment is one mention, which is also what stops a double @ from
    # sending two notifications.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_mentions_unique_index
      ON #{p}phoenix_kit_mentions (source_type, source_uuid, source_field, target_type, target_uuid)
    """)

    # "What links here" — the whole point of the table.
    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_mentions_target_index
      ON #{p}phoenix_kit_mentions (target_type, target_uuid)
    """)

    # The re-sync path deletes and re-inserts by source field.
    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_mentions_source_index
      ON #{p}phoenix_kit_mentions (source_type, source_uuid, source_field)
    """)

    # Pending @pings awaiting delivery.
    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_mentions_pending_index
      ON #{p}phoenix_kit_mentions (kind, notified_at) WHERE (notified_at IS NULL)
    """)

    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_access_requests (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      requester_uuid UUID NOT NULL REFERENCES #{p}phoenix_kit_users(uuid) ON DELETE CASCADE,
      resource_type TEXT NOT NULL,
      resource_uuid UUID NOT NULL,
      -- Where they hit the wall, so the owner can see the context that
      -- prompted the ask rather than a bare "someone wants in".
      source_type TEXT,
      source_uuid UUID,
      note TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      decided_by_uuid UUID REFERENCES #{p}phoenix_kit_users(uuid) ON DELETE SET NULL,
      decided_at TIMESTAMPTZ,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT phoenix_kit_access_requests_status_check
        CHECK (status IN ('pending', 'granted', 'denied', 'cancelled'))
    )
    """)

    # One OPEN request per person per resource: asking twice is the same ask,
    # and without this the owner's queue fills with duplicates from anyone
    # who clicks the button repeatedly. Partial, so a denied request doesn't
    # block asking again later when circumstances change.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_access_requests_open_index
      ON #{p}phoenix_kit_access_requests (requester_uuid, resource_type, resource_uuid)
      WHERE (status = 'pending')
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_access_requests_resource_index
      ON #{p}phoenix_kit_access_requests (resource_type, resource_uuid, status)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '165'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_access_requests")
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_mentions")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '164'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
