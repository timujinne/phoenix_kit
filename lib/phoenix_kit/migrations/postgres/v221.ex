defmodule PhoenixKit.Migrations.Postgres.V221 do
  @moduledoc """
  V221: a confirmation of a person's live session.

  `phoenix_kit_api_confirmations` gets a third kind of owner. A write that a live browser
  session asks for in process (`PhoenixKit.API.Executor.execute_as/5`) waits for the person
  to confirm it, and the row that holds it is bound to that person:

    * **`actor_user_uuid`** (`uuid`, nullable), the user the confirmation belongs to, with a
      foreign key to `phoenix_kit_users` `ON DELETE CASCADE`: deleting the user deletes
      their confirmations;
    * the **actor CHECK** (`phoenix_kit_api_confirmations_actor_check`) is recreated so that
      a row may name a user instead of a key or a client token;
    * an index on **`(actor_user_uuid, status)`**: the user's lookups, and the cascade of a
      user delete.

  No row is created or changed.

  ## Locks

  One `ADD COLUMN` without a default (no table rewrite), the CHECK dropped and added in one
  `ALTER TABLE` (it reads the table once, under an exclusive lock: the table holds only
  short-lived codes), and one index. Re-runnable.

  ## Down

  Deletes the confirmations of sessions (they have no owner without the column), restores
  the CHECK of V220 and drops the index and the column. Re-runnable.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.V203

  @doc false
  def up(opts) do
    opts |> Map.get(:prefix, "public") |> up_statements() |> Enum.each(&execute/1)
  end

  @doc "Rolls V221 back: the confirmations of sessions and the column go."
  def down(opts) do
    opts |> Map.get(:prefix, "public") |> down_statements() |> Enum.each(&execute/1)
  end

  @doc false
  def up_statements(prefix) do
    p = V203.prefix_str(prefix)
    conf = "#{p}phoenix_kit_api_confirmations"

    [
      "ALTER TABLE #{conf} ADD COLUMN IF NOT EXISTS actor_user_uuid uuid",
      """
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE c.conname = 'phoenix_kit_api_confirmations_actor_user_uuid_fkey'
            AND t.relname = 'phoenix_kit_api_confirmations'
            AND n.nspname = '#{prefix}'
        ) THEN
          ALTER TABLE #{conf}
            ADD CONSTRAINT phoenix_kit_api_confirmations_actor_user_uuid_fkey
            FOREIGN KEY (actor_user_uuid) REFERENCES #{p}phoenix_kit_users(uuid) ON DELETE CASCADE;
        END IF;
      END
      $$
      """,
      """
      ALTER TABLE #{conf}
        DROP CONSTRAINT IF EXISTS phoenix_kit_api_confirmations_actor_check,
        ADD CONSTRAINT phoenix_kit_api_confirmations_actor_check
          CHECK (actor_key_uuid IS NOT NULL OR cart_token_hash IS NOT NULL OR actor_user_uuid IS NOT NULL)
      """,
      # A user's lookups, and the cascade of a user delete.
      "CREATE INDEX IF NOT EXISTS phoenix_kit_api_confirmations_actor_user_status_index ON #{conf} (actor_user_uuid, status)",
      "COMMENT ON TABLE #{p}phoenix_kit IS '221'"
    ]
  end

  @doc false
  def down_statements(prefix) do
    p = V203.prefix_str(prefix)
    conf = "#{p}phoenix_kit_api_confirmations"

    [
      # A session's row cannot satisfy the CHECK of V220.
      """
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = '#{prefix}'
            AND table_name = 'phoenix_kit_api_confirmations'
            AND column_name = 'actor_user_uuid'
        ) THEN
          DELETE FROM #{conf} WHERE actor_user_uuid IS NOT NULL;
        END IF;
      END
      $$
      """,
      """
      ALTER TABLE #{conf}
        DROP CONSTRAINT IF EXISTS phoenix_kit_api_confirmations_actor_check,
        ADD CONSTRAINT phoenix_kit_api_confirmations_actor_check
          CHECK (actor_key_uuid IS NOT NULL OR cart_token_hash IS NOT NULL)
      """,
      "DROP INDEX IF EXISTS #{p}phoenix_kit_api_confirmations_actor_user_status_index",
      "ALTER TABLE #{conf} DROP COLUMN IF EXISTS actor_user_uuid",
      "COMMENT ON TABLE #{p}phoenix_kit IS '220'"
    ]
  end
end
