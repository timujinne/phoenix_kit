defmodule PhoenixKit.API.Idempotency.Record do
  @moduledoc """
  One `Idempotency-Key` an API client used (table `phoenix_kit_api_idempotency`).

    * `scope_ref` - the key uuid (admin calls) or the client-token hash (public
      calls); `{scope_ref, key}` is unique.
    * `request_hash` - canonical hash of the tool and its arguments, so a retry is
      told from a different request.
    * `state` - `"in_progress"` while the first request runs, `"done"` once its
      response is stored.
    * `locked_at` - the start of the lease (microseconds); also the token a claim
      compares against.
    * `response` - the exact JSON body of the stored `200` response.

  The logic is in `PhoenixKit.API.Idempotency`.
  """
  use Ecto.Schema
  use PhoenixKit.SchemaPrefix

  @type t :: %__MODULE__{}

  @primary_key {:uuid, UUIDv7, autogenerate: true}

  schema "phoenix_kit_api_idempotency" do
    field :scope_ref, :string
    field :key, :string
    field :request_hash, :string
    field :state, :string
    field :locked_at, :utc_datetime_usec
    field :response, :string
    field :expires_at, :utc_datetime

    timestamps(type: :utc_datetime, updated_at: false)
  end
end
