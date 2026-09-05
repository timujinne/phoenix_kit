defmodule PhoenixKit.Annotations.Annotation do
  @moduledoc """
  Ecto schema for `phoenix_kit_annotations`.

  Stores user-drawn shapes (rectangle, circle, polygon, freehand) tied to
  a **target**: `target_type` + `target_uuid`, Etcher's own vocabulary.
  A `"file"` target is a `PhoenixKit.Modules.Storage.File` and carries its
  uuid in `file_uuid` as well (the hard FK every file-side feature — the
  thumbnail job, `has_annotations?/1`, the comment threads — keys on).
  Any other target (a projects whiteboard, say) carries NO file: the
  shapes sit on an empty Fresco canvas. V183 pins the two shapes with a
  CHECK. All geometry is in canvas-pixel coordinates; Fresco's coordinate
  adapter rescales for pan/zoom at render time.

  ## Comment thread linkage

  An annotation's discussion lives in `phoenix_kit_comments` anchored to
  the **file** (`resource_type = "file"`, `resource_uuid = file_uuid`)
  with `metadata.annotation_uuid` carrying the back-reference. This lets
  annotation-rooted comments appear in the file's main comments thread
  alongside non-annotated discussion. There is no `comment_uuid` column
  on annotations — the relationship is one-directional from the comment
  side, and a thread is created lazily when the first comment is posted.
  """
  use Ecto.Schema
  use PhoenixKit.SchemaPrefix
  import Ecto.Changeset

  @primary_key {:uuid, UUIDv7, autogenerate: true}
  @foreign_key_type UUIDv7

  @kinds ~w(rectangle circle polygon freehand callout text dimension line marker image)

  @type t :: %__MODULE__{
          uuid: UUIDv7.t() | nil,
          file_uuid: UUIDv7.t() | nil,
          target_type: String.t(),
          target_uuid: UUIDv7.t() | nil,
          creator_uuid: UUIDv7.t() | nil,
          kind: String.t(),
          geometry: map(),
          style: map() | nil,
          metadata: map() | nil,
          position: integer(),
          title: String.t() | nil,
          inserted_at: DateTime.t() | nil,
          updated_at: DateTime.t() | nil
        }

  schema "phoenix_kit_annotations" do
    field :file_uuid, UUIDv7
    field :target_type, :string, default: "file"
    field :target_uuid, UUIDv7
    field :creator_uuid, UUIDv7
    field :kind, :string
    field :geometry, :map
    field :style, :map
    field :metadata, :map
    field :position, :integer, default: 0
    field :title, :string

    timestamps(type: :utc_datetime)
  end

  # Shape of a `target_type`. Lowercase, ≤ 32 characters, so it fits the
  # column (`character varying(32)`) and reads as an identifier rather than
  # free text. Public so the Etcher adapter shares it instead of keeping a
  # second copy to drift from — the same reason `adapter_writable_fields/0`
  # exists.
  @target_type_format ~r/\A[a-z][a-z0-9_]{0,31}\z/

  @cast_fields ~w(uuid file_uuid target_type target_uuid creator_uuid kind geometry style metadata position title)a
  @required_fields ~w(target_type target_uuid kind geometry)a

  # Fields the storage adapter is allowed to accept from event payloads.
  # `file_uuid` is set server-side from `target_uuid`, not by the client,
  # so it's excluded here — the adapter's `create/1` puts it on the
  # changeset after the whitelist filter. `creator_uuid` is set server-
  # side from the actor (`adapter`'s `create/1` resolves it from the
  # actor opts), so it's excluded for the same reason — a forged event
  # payload shouldn't be able to claim authorship.
  @adapter_writable_fields @cast_fields -- [:file_uuid, :target_type, :target_uuid, :creator_uuid]

  @doc false
  def changeset(annotation, attrs) do
    annotation
    |> cast(attrs, @cast_fields)
    |> put_file_target()
    |> validate_required(@required_fields)
    |> validate_inclusion(:kind, @kinds)
    |> validate_length(:title, max: 200)
    # On the CHANGESET, not only in the adapter. The adapter is not the sole
    # writer: `Annotations.create/1` is public and is the path a board takes,
    # so without this a `target_type` over 32 characters reached
    # `character varying(32)` and came back as a raw Postgres error — the exact
    # thing `validate_target/1` below exists to prevent one field over.
    |> validate_format(:target_type, @target_type_format,
      message: "must be lowercase letters, digits or underscores, at most 32 characters"
    )
    |> validate_target()
    |> foreign_key_constraint(:file_uuid)
    |> check_constraint(:target_type, name: :phoenix_kit_annotations_target_check)
    |> foreign_key_constraint(:creator_uuid)
    |> check_constraint(:kind, name: :phoenix_kit_annotations_kind_check)
  end

  # A caller that only knows the file (every pre-V183 call site) gets the
  # target filled in: `file_uuid` given and no target ⇒ a file target.
  defp put_file_target(changeset) do
    file_uuid = get_field(changeset, :file_uuid)

    case {file_uuid, get_field(changeset, :target_uuid)} do
      {uuid, nil} when is_binary(uuid) ->
        changeset |> put_change(:target_type, "file") |> put_change(:target_uuid, uuid)

      _ ->
        changeset
    end
  end

  # The V183 CHECK, mirrored here so the error is a changeset error and
  # not a constraint exception: a file target carries the file in both
  # columns; any other target carries no file.
  defp validate_target(changeset) do
    type = get_field(changeset, :target_type)
    target = get_field(changeset, :target_uuid)
    file = get_field(changeset, :file_uuid)

    cond do
      type == "file" and (is_nil(file) or file != target) ->
        add_error(changeset, :file_uuid, "a file target must carry its file uuid")

      type != "file" and not is_nil(file) ->
        add_error(changeset, :file_uuid, "only a file target carries a file uuid")

      true ->
        changeset
    end
  end

  @doc "List of allowed kind strings."
  def kinds, do: @kinds

  @doc """
  Shape a `target_type` must have.

  Shared with the Etcher adapter, which rejects a malformed target before
  building attrs at all (the protocol wants `{:error, :unsupported_target}`,
  not a changeset). One regex so the two answers cannot disagree.
  """
  @spec target_type_format() :: Regex.t()
  def target_type_format, do: @target_type_format

  @doc """
  Fields the Etcher storage adapter is allowed to take from event
  payloads. Single source of truth so the adapter's whitelist doesn't
  drift from the schema's `@cast_fields`. The target columns are
  excluded — the adapter sets them server-side from the Etcher
  `target_type` / `target_uuid`, never from the payload.
  """
  @spec adapter_writable_fields() :: [atom()]
  def adapter_writable_fields, do: @adapter_writable_fields
end
