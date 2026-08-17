defmodule PhoenixKit.Annotations do
  # PhoenixKitComments is an optional sibling package. The preview-loader
  # (`list_for_file_with_previews/1`) guards every call with
  # `Code.ensure_loaded?/1` and gracefully degrades when comments aren't
  # installed; silence the undefined warnings the compiler would emit.
  @compile {:no_warn_undefined, [PhoenixKitComments]}

  @moduledoc """
  Context for `phoenix_kit_annotations` — drawn-on-image shapes created
  via the Etcher overlay layer in the MediaBrowser modal.

  Most callers won't use this directly — they go through
  `PhoenixKit.Modules.Storage.EtcherAdapter` which implements the
  `Etcher.Storage` behaviour and dispatches to this context. The module
  is exposed so admin tooling, audits, or background workers can do
  CRUD without reaching for the adapter.
  """

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.Annotations.Annotation
  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Modules.Storage.URLSigner
  alias PhoenixKit.RepoHelper

  @type attrs :: map()
  @type uuid :: String.t()

  @doc """
  Create an annotation for a file.

  `attrs` accepts both atom- and string-keyed maps (the latter is what
  flows in from LiveView events). Keys: `:file_uuid`, `:kind`,
  `:geometry`, optional `:creator_uuid`, `:style`, `:metadata`,
  `:position`.
  """
  @spec create(attrs()) :: {:ok, Annotation.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %Annotation{}
    |> Annotation.changeset(attrs)
    |> RepoHelper.insert()
  end

  @doc "Returns true if the file has at least one annotation."
  @spec has_annotations?(term()) :: boolean()
  def has_annotations?(file_uuid) when is_binary(file_uuid) do
    RepoHelper.exists?(from a in Annotation, where: a.file_uuid == ^file_uuid)
  end

  def has_annotations?(_), do: false

  @doc """
  Resolves `"file"` comment resources for the comments moderation admin.

  Comments on files — including annotation discussions, which are anchored to
  the file with `metadata.annotation_uuid` — carry `resource_type: "file"` and
  `resource_uuid: file_uuid`. This maps those file uuids to the file's display
  name and admin media path so the moderation list links to the file instead
  of showing a bare uuid.

  Registered as the `"file"` handler by `phoenix_kit_comments`'
  `resolve_comment_resources/1` dispatch (gated on this module being loaded).
  """
  @spec resolve_comment_resources([uuid()]) :: %{uuid() => map()}
  def resolve_comment_resources(resource_uuids) when is_list(resource_uuids) do
    from(f in StorageFile,
      where: f.uuid in ^resource_uuids,
      select: {f.uuid, f.original_file_name, f.file_name, f.file_type}
    )
    |> RepoHelper.all()
    |> Map.new(fn {uuid, original_name, file_name, file_type} ->
      # Return a RAW path — the comments module applies Routes.path/1 once when
      # rendering the chip. Pre-applying it here double-prefixed the URL under a
      # non-root url_prefix.
      info = %{
        title: original_name || file_name || "File",
        path: "/admin/media/#{uuid}"
      }

      # A small signed thumbnail for image files, so the comments admin can show
      # a preview chip. Falls back to no thumb for non-images (or missing variants).
      info =
        if file_type == "image",
          do: Map.put(info, :thumb_url, URLSigner.signed_url(to_string(uuid), "thumbnail")),
          else: info

      {uuid, info}
    end)
  rescue
    _ -> %{}
  end

  @doc "List annotations for a file, ordered by `position` then insertion time."
  @spec list_for_file(uuid()) :: [Annotation.t()]
  def list_for_file(file_uuid) do
    RepoHelper.all(
      from a in Annotation,
        where: a.file_uuid == ^file_uuid,
        order_by: [asc: a.position, asc: a.inserted_at]
    )
  end

  @doc """
  List annotations for a file together with a tooltip-friendly preview of
  their comment thread. Each element is a map:

      %{
        annotation: %Annotation{},
        first_comment: %{content, author, thumbnail_url} | nil,
        comment_count: integer(),
        master_comment_uuid: String.t() | nil
      }

  `comment_count` counts the DISCUSSION — the master/topic comment a
  shape's thread hangs under (`metadata.annotation_master`) is excluded,
  and its uuid is surfaced as `master_comment_uuid` (nil until the first
  Reply creates it) so callers can thread new messages under it.

  Annotation comments are stored against the file (`resource_type: "file"`,
  `resource_uuid: file_uuid`) with `metadata.annotation_uuid` pointing at
  the annotation, so they show up in the file's main comments thread
  alongside non-annotated discussion. This loader pulls every file
  comment in one query and groups by that metadata key.

  If the comments package isn't installed, returns the same shape with
  `first_comment: nil` and `comment_count: 0` so callers always handle
  one schema.
  """
  @spec list_for_file_with_previews(uuid()) :: [map()]
  def list_for_file_with_previews(file_uuid) do
    annotations = list_for_file(file_uuid)

    by_annotation =
      if Code.ensure_loaded?(PhoenixKitComments) do
        group_file_comments_by_annotation(file_uuid)
      else
        %{}
      end

    Enum.map(annotations, fn ann ->
      comments = Map.get(by_annotation, ann.uuid, [])
      Map.merge(%{annotation: ann}, build_preview(comments))
    end)
  end

  defp group_file_comments_by_annotation(file_uuid) do
    all = PhoenixKitComments.list_comments("file", file_uuid, preload: [:user, media: :file])

    # Build a parent_uuid → [children] map so we can walk the tree from
    # each annotation-rooted comment and pick up every reply. The
    # tooltip's count should reflect total activity on the annotation,
    # not just the root post.
    children_by_parent = Enum.group_by(all, & &1.parent_uuid)

    all
    |> Enum.filter(fn c -> is_binary(get_in(c.metadata || %{}, ["annotation_uuid"])) end)
    |> Enum.reduce(%{}, fn root, acc ->
      annotation_uuid = get_in(root.metadata, ["annotation_uuid"])
      cluster = collect_subtree(root, children_by_parent)
      Map.update(acc, annotation_uuid, cluster, &(&1 ++ cluster))
    end)
  end

  defp collect_subtree(root, children_by_parent) do
    children = Map.get(children_by_parent, root.uuid, [])
    [root | Enum.flat_map(children, &collect_subtree(&1, children_by_parent))]
  end

  # Comments arrive ordered by inserted_at asc from list_comments/3, so
  # the first top-level entry is the earliest reply. If everything is a
  # reply (rare — usually there's a root), fall back to the first.
  #
  # The MASTER comment — the topic row a shape's discussion hangs under
  # (`metadata.annotation_master`, created lazily on the first Reply and
  # backdated to the shape's creation) — is bookkeeping, not discussion:
  # its content is the shape's own label, so counting it would say "1
  # comment" about a shape nobody has said anything about, and previewing
  # it would echo the label the tooltip is already showing. It is
  # excluded from both and surfaced as `master_comment_uuid` instead, so
  # the Reply flow can thread new messages under it (nil = not created
  # yet). Pre-master rows (composer-posted anchors from older installs)
  # carry no marker and keep counting as discussion.
  defp build_preview([]),
    do: %{first_comment: nil, comment_count: 0, master_comment_uuid: nil}

  defp build_preview(comments) do
    {masters, discussion} =
      Enum.split_with(comments, fn c ->
        get_in(c.metadata || %{}, ["annotation_master"]) == true
      end)

    first =
      case Enum.find(discussion, fn c -> c.parent_uuid == nil end) do
        nil -> List.first(discussion)
        c -> c
      end

    %{
      first_comment: build_first_comment(first),
      comment_count: length(discussion),
      master_comment_uuid: masters |> List.first() |> then(&(&1 && to_string(&1.uuid)))
    }
  end

  defp build_first_comment(nil), do: nil

  defp build_first_comment(comment) do
    %{
      content: comment.content,
      author: author_display(comment.user),
      thumbnail_url: first_attachment_thumbnail(comment) || giphy_preview(comment),
      # `has_attachment` lets the tooltip render a paperclip fallback
      # icon when the comment has media but no usable thumbnail URL
      # (e.g. variant generation hasn't completed yet, or the file
      # isn't an image so there's no preview to render).
      has_attachment: has_any_media?(comment)
    }
  end

  defp has_any_media?(%{media: media}) when is_list(media) and media != [], do: true
  defp has_any_media?(_), do: false

  defp author_display(nil), do: nil

  defp author_display(user) do
    case {user.first_name, user.last_name, user.email} do
      {fn_, ln, _} when is_binary(fn_) and is_binary(ln) and fn_ != "" and ln != "" ->
        "#{fn_} #{ln}"

      {fn_, _, _} when is_binary(fn_) and fn_ != "" ->
        fn_

      {_, _, email} when is_binary(email) ->
        email |> String.split("@", parts: 2) |> hd()

      _ ->
        nil
    end
  end

  defp first_attachment_thumbnail(comment) do
    # `comment.media` is `%Ecto.Association.NotLoaded{}` when the
    # preload didn't fire, an empty list for a no-attachment comment,
    # or a list of `CommentMedia` rows (the smallest position first per
    # the schema's `preload_order`).
    #
    # Walk the available variants smallest-first.
    # `get_public_url_by_variant` already falls back to the original
    # when the requested variant doesn't exist, but we still want to
    # land on "thumbnail" when it's there. Non-image files (PDF, zip,
    # audio) have no thumbnail; for those the JS picks up
    # `has_attachment` and renders a paperclip icon instead.
    case comment.media do
      [%{file: %StorageFile{} = file} | _] ->
        if image?(file), do: Storage.get_public_url_by_variant(file, "thumbnail"), else: nil

      _ ->
        nil
    end
  end

  defp image?(%StorageFile{mime_type: "image/" <> _}), do: true
  defp image?(_), do: false

  defp giphy_preview(%{metadata: %{"giphy" => %{"preview_url" => url}}}) when is_binary(url),
    do: url

  defp giphy_preview(_), do: nil

  @doc "Fetch a single annotation by UUID, or nil."
  @spec get(uuid()) :: Annotation.t() | nil
  def get(uuid), do: RepoHelper.get(Annotation, uuid)

  @doc "Update an annotation's geometry / style / metadata / position."
  @spec update(uuid(), attrs()) ::
          {:ok, Annotation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update(uuid, attrs) do
    case RepoHelper.get(Annotation, uuid) do
      nil ->
        {:error, :not_found}

      annotation ->
        # `:uuid` is castable so client-generated UUIDv7s survive INSERT,
        # but on UPDATE casting it would let a stray payload uuid rewrite
        # the primary key. The row is already located by `uuid` above —
        # strip it so the changeset can't touch the PK.
        annotation
        |> Annotation.changeset(Map.drop(attrs, [:uuid, "uuid"]))
        |> RepoHelper.update()
    end
  end

  @doc """
  Delete an annotation by UUID.

  Cascades to any linked comments — i.e. comments on the annotation's
  file that carry `metadata.annotation_uuid` pointing at this row. The
  cascade is a hard delete: annotation comments are conceptually owned
  by their annotation, so they go with it instead of lingering as
  `[removed]` placeholders in the file's thread. `phoenix_kit_comment_media`
  rows fall away via their `ON DELETE CASCADE`; the underlying media
  files (referenced via `comment_media.file_uuid`) stay untouched —
  they're library assets, not comment-owned. No-ops cleanly when
  PhoenixKitComments isn't installed.
  """
  @spec delete(uuid()) :: :ok | {:error, :not_found | Ecto.Changeset.t()}
  def delete(uuid) do
    case RepoHelper.get(Annotation, uuid) do
      nil -> {:error, :not_found}
      annotation -> delete_in_transaction(annotation)
    end
  end

  # Atomicity: delete linked comments and the annotation row in a single
  # transaction so a failure between the two doesn't leave the annotation
  # alive with its discussion thread destroyed (or vice-versa). The
  # comment-side cleanup is best-effort via its own rescue (see
  # `delete_linked_comments/1`); the annotation delete is the load-bearing
  # write that must succeed or roll back.
  defp delete_in_transaction(annotation) do
    repo = RepoHelper.repo()

    fun = fn ->
      delete_linked_comments(annotation)

      case RepoHelper.delete(annotation) do
        {:ok, _} -> :ok
        {:error, cs} -> repo.rollback(cs)
      end
    end

    case repo.transaction(fun) do
      {:ok, :ok} -> :ok
      {:error, %Ecto.Changeset{} = cs} -> {:error, cs}
      {:error, reason} -> {:error, reason}
    end
  end

  defp delete_linked_comments(annotation) do
    if Code.ensure_loaded?(PhoenixKitComments) do
      # Iterate via the PhoenixKitComments wrapper (avoids a compile-
      # time reference to the optional dep's schema module) and hard-
      # delete each match via Repo.delete on the struct. ON DELETE
      # CASCADE on `phoenix_kit_comment_media.comment_uuid` drops the
      # attachment link rows; underlying media files stay.
      repo = RepoHelper.repo()

      "file"
      |> PhoenixKitComments.list_comments(annotation.file_uuid)
      |> Enum.filter(fn c ->
        get_in(c.metadata || %{}, ["annotation_uuid"]) == annotation.uuid
      end)
      |> Enum.each(fn c -> repo.delete(c) end)
    end
  rescue
    # Narrow rescue — swallow only the comment-side classes we expect so
    # logic bugs (KeyError, MatchError, etc.) surface to the supervisor
    # instead of leaving the annotation undeletable. Orphan comments
    # are benign (they show in the file thread without their pin) so a
    # comment-side `Postgrex.Error` shouldn't block annotation deletion;
    # `ArgumentError` covers `PhoenixKitComments` API churn (a renamed
    # function, a list_comments arity bump). The encompassing
    # transaction owns annotation-side atomicity (see `delete/1`).
    e in [DBConnection.OwnershipError, Postgrex.Error, ArgumentError] ->
      require Logger
      Logger.warning("[Annotations] delete_linked_comments: #{Exception.message(e)}")
      :ok
  end
end
