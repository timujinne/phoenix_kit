defmodule PhoenixKit.Mentions.AccessRequest do
  @moduledoc """
  Someone asking to be let in to a record a mention pointed them at.

  A `#` link to something the reader cannot open tells them it exists and
  nothing else. That is only useful if there is a next step, so the redacted
  chip offers one: ask the people who own it.

  `status` is a string sentinel per the workspace's soft-delete convention.
  A `pending` request is unique per (requester, resource) — asking twice is
  the same ask — but the index is partial, so a denied request never blocks
  asking again when circumstances change.
  """
  use Ecto.Schema
  use PhoenixKit.SchemaPrefix
  import Ecto.Changeset

  @primary_key {:uuid, UUIDv7, autogenerate: true}
  @foreign_key_type UUIDv7

  @statuses ~w(pending granted denied cancelled)

  @type t :: %__MODULE__{
          uuid: UUIDv7.t() | nil,
          requester_uuid: UUIDv7.t() | nil,
          resource_type: String.t() | nil,
          resource_uuid: UUIDv7.t() | nil,
          source_type: String.t() | nil,
          source_uuid: UUIDv7.t() | nil,
          note: String.t() | nil,
          status: String.t() | nil,
          decided_by_uuid: UUIDv7.t() | nil,
          decided_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil,
          updated_at: DateTime.t() | nil
        }

  schema "phoenix_kit_access_requests" do
    field(:requester_uuid, UUIDv7)
    field(:resource_type, :string)
    field(:resource_uuid, UUIDv7)
    field(:source_type, :string)
    field(:source_uuid, UUIDv7)
    field(:note, :string)
    field(:status, :string, default: "pending")
    field(:decided_by_uuid, UUIDv7)
    field(:decided_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  @required ~w(requester_uuid resource_type resource_uuid)a
  @optional ~w(source_type source_uuid note status decided_by_uuid decided_at)a

  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(request, attrs) do
    request
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_inclusion(:status, @statuses)
    # The note is shown to whoever decides. Capped because it lands in a
    # notification body, not a document.
    |> validate_length(:note, max: 500)
    |> unique_constraint([:requester_uuid, :resource_type, :resource_uuid],
      name: :phoenix_kit_access_requests_open_index,
      message: "already requested"
    )
  end

  @spec statuses() :: [String.t()]
  def statuses, do: @statuses
end
