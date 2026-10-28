defmodule PhoenixKit.Migrations.Postgres.V223 do
  @moduledoc """
  V223: an AI request's cost in dollars, and the AI tables' leftovers cleared.

  ## The cost

  `phoenix_kit_ai_requests.cost_cents` never held cents: `phoenix_kit_ai` stored a
  provider's reported cost as `round(dollars * 1_000_000)`, millionths of a dollar, so a
  cheap call (a short embedding costs about $0.0000001) was stored as `0`, and every
  reader had to divide.

  The column becomes **`cost`**, a **`numeric(28,18)`** amount of US dollars, like every
  other amount of money in the kit (`price`, `total`, `amount`): `0.00003` is three
  thousandths of a cent. Eighteen decimal places (an attodollar) keep the cheapest
  single tokens with room to spare: a cached input token at $0.0014 per million
  (OpenRouter's cheapest in 2026) is `0.0000000014`, and a small embedding model run
  locally, priced at its electricity, is about `0.0000000001` a token — prices keep
  falling, and a scale is costly to change once released. Postgres stores a numeric's
  significant digits, not its declared scale, so the places cost nothing. The stored
  costs are converted in the same rewrite (`cost_cents / 1_000_000`). The rename is
  deliberate: a `phoenix_kit_ai` that still writes millionths fails on the missing column
  instead of storing costs a million times too large. A database that ran an unreleased
  V223 holding `cost_nanodollars` (billionths, `bigint`) is converted the same way
  (`/ 1_000_000_000`). The AI settings (spend caps, task limits, prices) are converted by
  `phoenix_kit_ai`'s own migration chain, not here.

  ## The leftovers

    * **`phoenix_kit_ai_requests.model`** is widened to `varchar(150)`, the width of
      `phoenix_kit_ai_endpoints.model`: a longer model id failed the usage row's insert,
      so its spend went uncounted.
    * **`phoenix_kit_ai_accounts`** (the provider accounts from before V34's endpoints —
      name, provider, a plaintext API key) and **`phoenix_kit_ai_requests.account_uuid`**
      are dropped. Nothing has read either since V34, which kept the table "for
      historical request references" and never copied it into the endpoints. The number
      of rows dropped is raised as a NOTICE.
    * **Unique indexes on `uuid` beside a primary key** on the endpoints, prompts and
      requests tables (`phoenix_kit_ai_endpoints_uuid_idx`, `phoenix_kit_ai_prompts_uuid_idx`
      — `<prefix>_…` outside `public` — `phoenix_kit_ai_prompts_uuid_index`,
      `phoenix_kit_ai_requests_uuid_idx`) are dropped. They are found by shape (unique,
      btree, on `uuid` alone, no predicate, not a constraint's own), not by name. A foreign
      key bound to one of them (Postgres binds a key to the first matching unique index,
      and these predate the primary keys) blocks its drop, so every such key — this
      module's or another's — is dropped first and added again after, with the same name
      and definition, now bound to the primary key.

  Everything structural is one `DO` block, so it is atomic even though the wrappers this
  chain runs under have no enclosing transaction, and a re-run finds nothing left to do
  (a key is added back only when it is missing). `search_path` is emptied inside it so
  the re-added keys' definitions name their schemas. Cost beside a legacy cost column,
  or both legacy columns, stops the migration instead.

  Needs the `phoenix_kit_ai` release that writes `cost` and no longer reads `account_uuid`.

  ## Locks

  `ALTER COLUMN … TYPE` rewrites the requests table and its indexes once, under an
  `ACCESS EXCLUSIVE` lock held until the block ends: AI calls wait to write their usage
  rows, and spend checks wait to read them. Re-adding the foreign keys checks every row
  of the referencing tables again — the requests table twice (endpoint, prompt) — inside
  the same lock. The accounts table, the guard events and the task settings are small.

  ## Down

  Back to the V222 shape: the costs in integer millionths (`cost_cents`; finer precision
  is lost, a row above $2,147.48 stops the rollback), `model` narrowed to `varchar(100)`
  (a longer model stops the rollback), the four duplicate indexes recreated (the foreign
  keys stay on the primary keys), and an EMPTY `phoenix_kit_ai_accounts` with its
  indexes and an empty `account_uuid` — the rows and keys dropped do not come back.

  ## Core 3.0

  Everything this version did belonged to a module's tables and now lives in
  that module's own migration chain (`PhoenixKit.Migrations.ModuleOwnedTables`,
  plan `dev_docs/plans/2026-10-25-module-table-ownership.md`, step 8): core no
  longer creates or changes them. The version is kept so the chain stays
  numbered; it only moves the marker. Hosts below V225 cannot upgrade to this
  release (`BelowFloorError`), so nobody replays what the text above describes.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '223'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '222'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
