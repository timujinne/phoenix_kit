defmodule PhoenixKit.Mentions.Mention do
  @moduledoc """
  One `@` ping or `#` record link, indexed.

  The canonical mention is the token inside the text — see
  `PhoenixKit.Mentions.Token` for why. This row is a rebuilt-on-save cache
  of the current head of one field, and exists to answer two questions the
  text cannot answer cheaply:

    * **what links here** — every record pointing at this one, without
      scanning every body in every module;
    * **what is new** — so re-saving a comment doesn't re-notify everyone
      already mentioned in it.

  Neither side carries a foreign key: both point into ~28 optional
  packages' tables. `actor_uuid` does, because users are core's.
  """
  use Ecto.Schema
  use PhoenixKit.SchemaPrefix
  import Ecto.Changeset

  alias PhoenixKit.Mentions.Token

  @primary_key {:uuid, UUIDv7, autogenerate: true}
  @foreign_key_type UUIDv7

  @kinds ~w(user resource)

  @type t :: %__MODULE__{
          uuid: UUIDv7.t() | nil,
          source_type: String.t() | nil,
          source_uuid: UUIDv7.t() | nil,
          source_field: String.t() | nil,
          kind: String.t() | nil,
          target_type: String.t() | nil,
          target_uuid: UUIDv7.t() | nil,
          label: String.t() | nil,
          actor_uuid: UUIDv7.t() | nil,
          notified_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil
        }

  schema "phoenix_kit_mentions" do
    field(:source_type, :string)
    field(:source_uuid, UUIDv7)
    field(:source_field, :string, default: "body")
    field(:kind, :string)
    field(:target_type, :string)
    field(:target_uuid, UUIDv7)
    field(:label, :string)
    field(:actor_uuid, UUIDv7)
    field(:notified_at, :utc_datetime)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @required ~w(source_type source_uuid source_field kind target_type target_uuid)a
  @optional ~w(label actor_uuid notified_at)a

  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(mention, attrs) do
    mention
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_inclusion(:kind, @kinds)
    |> validate_length(:label, max: Token.max_label_length())
    |> unique_constraint([:source_type, :source_uuid, :source_field, :target_type, :target_uuid],
      name: :phoenix_kit_mentions_unique_index
    )
    # The actor can be deleted between opening the form and saving it. That
    # should cost the attribution, not the save.
    |> foreign_key_constraint(:actor_uuid)
  end

  @doc "The two mention kinds: an `@` ping and a `#` record link."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds
end
