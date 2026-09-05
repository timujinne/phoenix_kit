defmodule PhoenixKit.Modules.Storage.EtcherAdapter do
  @moduledoc """
  Persistence helper for the MediaBrowser's annotation flow.

  Etcher 0.3 dropped the `Etcher.Storage` behaviour entirely — annotations
  now live inside the host `<Fresco.canvas>`'s `extensions.etcher` blob
  and the library doesn't reach into the consumer's DB anymore. PhoenixKit
  still needs to persist its annotations (they're per-file, not per-canvas-
  file-on-disk), so this module survives as a thin helper module called
  from the MediaBrowser LV's `etcher:annotations-changed` event handler —
  not as a behaviour implementation.

  The four public functions (`create/1`, `list_for/2`, `update/2`,
  `delete/1`) keep their pre-0.3 signatures so the diff in MediaBrowser
  stays small. None of them are `@impl` annotations anymore; they're
  just plain helpers wrapping the `PhoenixKit.Annotations` context.

  Etcher's generic API is keyed by `target_type` + `target_uuid` so the
  library can annotate any kind of resource. A `"file"` target is a media
  File and is stored with `file_uuid` set as well (the hard FK the
  file-side features key on); any other target — a projects whiteboard,
  say — is stored by the pair alone, with no file (V183). Both shapes
  are pinned by the schema and a CHECK.

  ## Comment threads

  An annotation's discussion thread is **not** created at draw time —
  it's instantiated lazily when the user posts the first comment on the
  annotation. The comments are anchored to the **file**
  (`resource_type = "file"`, `resource_uuid = file_uuid`) with
  `metadata.annotation_uuid` carrying the back-reference, so they
  appear in the file's main thread alongside non-annotated discussion.
  No `comment_uuid` column on annotations is needed.
  """

  alias PhoenixKit.Annotations
  alias PhoenixKit.Annotations.Annotation

  # Whitelist of annotation schema fields the helper accepts from event
  # payloads, sourced from `Annotation.adapter_writable_fields/0` so the
  # set stays in sync with the schema's `@cast_fields`. Anything else
  # (Etcher routing keys, JS-side anchor coords, comment-derived metadata
  # we hydrate server-side) is silently dropped — `String.to_existing_atom`
  # on unknown payload keys used to crash the LV when Etcher's payload
  # shape grew new client-side keys. Stored as strings here since the
  # filter compares against `to_string(payload_key)`.
  @schema_keys Enum.map(Annotation.adapter_writable_fields(), &Atom.to_string/1)

  def create(attrs) do
    with {:ok, target_type, target_uuid} <- target(attrs) do
      attrs
      |> filter_to_schema()
      |> Map.put(:target_type, target_type)
      |> Map.put(:target_uuid, target_uuid)
      |> Map.put(:file_uuid, if(target_type == "file", do: target_uuid))
      |> Annotations.create()
    end
  end

  def list_for(target_type, target_uuid) when is_binary(target_type) and is_binary(target_uuid),
    do: Annotations.list_for_target(target_type, target_uuid)

  def list_for(_other, _uuid), do: []

  def update(uuid, attrs) do
    attrs
    |> filter_to_schema()
    |> then(&Annotations.update(uuid, &1))
  end

  def delete(uuid), do: Annotations.delete(uuid)

  # ---------------------------------------------------------------------------

  # The schema owns the shape; this is the early rejection the Etcher protocol
  # wants (`{:error, :unsupported_target}` rather than a changeset). Reading it
  # from `Annotation` keeps the two from drifting.

  defp target(%{"target_type" => type, "target_uuid" => uuid}), do: target(type, uuid)
  defp target(%{target_type: type, target_uuid: uuid}), do: target(type, uuid)
  defp target(_attrs), do: {:error, :unsupported_target}

  defp target(type, uuid) when is_binary(type) and is_binary(uuid) do
    if Regex.match?(Annotation.target_type_format(), type),
      do: {:ok, type, uuid},
      else: {:error, :unsupported_target}
  end

  defp target(_type, _uuid), do: {:error, :unsupported_target}

  defp filter_to_schema(attrs) do
    Enum.reduce(attrs, %{}, fn {k, v}, acc ->
      key = to_string(k)
      if key in @schema_keys, do: Map.put(acc, String.to_existing_atom(key), v), else: acc
    end)
  end
end
