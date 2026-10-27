defmodule PhoenixKitWeb.AnnotationBurnController do
  @moduledoc """
  Accepts a picture with its annotations already drawn into it, and stores
  that rendering as display variants.

  ## Why the client renders it

  The browser has the annotation layer on screen, drawn by the same engine
  that will draw it next time. Composing there means the stored picture IS
  what the user was looking at: the same fonts, the same label plates, the
  same smooth marker strokes, and no second renderer to keep in step with
  the first. `Etcher.Raster` remains the server-side path for backfill and
  for files nobody has open, where an approximation is the right trade.

  ## What this means for trust

  The bytes come from a client, so they are treated as a picture and nothing
  more: re-encoded through `ImageProcessor.sanitize/3` into the variant
  slot, never served back as uploaded. The caller must be signed in and
  allowed to edit the file, and the annotation set is not consulted — this
  endpoint replaces a rendering, it cannot change what the file's
  annotations ARE.

  ## What gets written

  The burn arrives at full resolution and is resized into whichever slots
  the caller names (`thumbnail` by default) in one request — making one is
  expensive enough that nobody should have to send it twice.

  Writable slots are `thumbnail` (list rows), `burned` (grid cards, fit
  inside an 800px box) and `burned_large` (the copy the media viewer opens
  with, fit inside 1920px). `small`, `medium`, `large` and `original` are not
  writable. The editor opens on `small` and climbs `medium` → `large` →
  `original`, drawing the live shapes on top; a burn stored in any of those
  would paint every annotation a second time. `original` stays the picture
  as uploaded for the same reason a rendering must stay removable.

  The client sends `source_version`, the `v` query of the original URL it
  composed over. When that names an original this file no longer has, the
  write is refused.
  """
  use PhoenixKitWeb, :controller

  require Logger

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.ImageProcessor
  alias PhoenixKit.Modules.Storage.Libraries
  alias PhoenixKit.Modules.Storage.URLSigner
  alias PhoenixKit.Modules.Storage.VariantGenerator
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User

  # A 5000px burn as JPEG is a few MB; the cap is generous enough for a
  # large board and small enough that nothing silly gets spooled to disk.
  @max_bytes 60 * 1024 * 1024
  # The slots a burn may be written into. The viewer's ladder
  # (`small` / `medium` / `large` / `original`) is deliberately absent.
  @writable ~w(thumbnail burned burned_large)
  @default_variants ~w(thumbnail)
  # Two burns, because the two readers want different things. Cards prefer
  # `burned` over the clean `small` (300px) and a grid paints many of them, so
  # it stays card-sized: a 1920px burn there made every annotated card
  # download and decode ~40x the pixels it shows. `burned_large` is the copy
  # the viewer OPENS with, sized to be looked at: 1080p-ish carries the markup
  # legibly on any screen anyone is reading it on, at a fraction of a
  # full-resolution compose. List rows keep the configured thumbnail (150px).
  # Anyone who wants the picture at its real size still has `original` —
  # these slots exist to be read and copied, not archived.
  @burned_edge 800
  @burned_large_edge 1920

  # The longest a fingerprint may be. It is a hash the client computes; a
  # length cap is all this side needs to know about it.
  @fingerprint_bytes 128

  @doc """
  `POST /api/files/:file_uuid/burn` — multipart, field `image`.

  Optional `variants` (`thumbnail`, `burned`, `burned_large`; default `thumbnail`),
  `source_version` (the original URL's `v`), and `fingerprint` — what the
  drawing was when this copy was made, handed back on the next open so a
  client with an unchanged drawing can skip the compose entirely.

  Answers with each variant that was written and a fresh signed URL for it,
  so a caller can show the result without guessing the URL or waiting for a
  page reload.
  """
  def create(conn, %{"file_uuid" => file_uuid} = params) do
    with {:ok, user} <- require_user(conn),
         {:ok, file} <- fetch_file(file_uuid),
         :ok <- ensure_image(file),
         :ok <- authorize(user, file),
         {:ok, upload} <- extract_image(params),
         {:ok, upload} <- readable_size(upload),
         :ok <- accept_magic(upload),
         {:ok, variants} <- variants_from_params(params),
         {:ok, source_key} <- bind_original(file, params),
         {:ok, written} <- write_variants(file, upload, variants, source_key, params) do
      # The fingerprint first, then the news: whoever re-reads the file on
      # the broadcast (the media browser refreshes its row and the open
      # viewer) must see what this copy was made from. Announced first, the
      # refresh raced the write and often kept the old answer — reopening
      # the picture and rubbing out its last shape then never rendered the
      # clean copy, because the page believed no burn was on file.
      remember_fingerprint(file, params["fingerprint"])
      Storage.broadcast_file_thumbnail_updated(file.uuid)
      json(conn, %{written: written})
    else
      {:error, reason} -> fail(conn, reason)
    end
  end

  def create(conn, _params), do: fail(conn, :no_file)

  @doc false
  def writable_variants, do: @writable

  # How a burn is kept, by what the stored file is — never by the upload:
  # the client's bytes only decide what is drawn, not how it is kept.
  #
  #   * an animated GIF stays a GIF that plays: the client sends only the
  #     markup, and the server draws it onto every frame (see
  #     `ImageProcessor.composite_animation/4`);
  #   * a picture that can be see-through (PNG, WebP, AVIF) burns as a PNG,
  #     lossless and with its transparency kept;
  #   * anything else — a photo — burns as WebP: about JPEG's size, but the
  #     margin around the picture that markup drawn past its edges opens up
  #     stays see-through instead of being filled white.
  @doc false
  def burn_format_for(mime) when is_binary(mime) do
    cond do
      mime == "image/gif" -> "gif"
      mime in ~w(image/png image/webp image/avif) -> "png"
      true -> "webp"
    end
  end

  def burn_format_for(_), do: "webp"

  @formats %{
    "gif" => {"gif", "image/gif"},
    "png" => {"png", "image/png"},
    "webp" => {"webp", "image/webp"}
  }

  defp ext_mime(format), do: Map.fetch!(@formats, format)

  @doc false
  # The file's owner, an Owner/Admin (honouring the active role), or anyone
  # holding the media module — the same three `ImageEditing` allows to change
  # the picture. Not a file of a managed library (`Libraries.managed?/1`).
  # `User.admin?/1` misses both the active role and a media permission
  # holder, who can already draw on the file.
  def allowed?(%{user_uuid: owner} = file, %User{uuid: uuid}, scope) do
    # A managed library's files are burned on by none, their owner included:
    # first, before the owner's own right.
    not Libraries.managed?(file) and
      ((is_binary(owner) and owner == uuid) or
         Libraries.can?(scope, file, :edit))
  end

  @doc false
  def variants_from_params(params) when is_map(params) do
    asked =
      case params["variants"] || params["variant"] do
        list when is_list(list) -> list
        name when is_binary(name) -> String.split(name, ",", trim: true)
        _ -> @default_variants
      end
      |> Enum.map(fn
        name when is_binary(name) -> String.trim(name)
        _ -> ""
      end)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    cond do
      asked == [] -> {:ok, @default_variants}
      Enum.all?(asked, &(&1 in @writable)) -> {:ok, asked}
      true -> {:error, :bad_variant}
    end
  end

  @doc false
  # JPEG, PNG or WebP, by magic. The multipart content-type is the client's claim.
  def image_magic?(<<0xFF, 0xD8, 0xFF, _::binary>>), do: true

  def image_magic?(<<"RIFF", _::binary-size(4), "WEBP", _::binary>>), do: true

  def image_magic?(<<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, _::binary>>), do: true

  def image_magic?(_), do: false

  @doc false
  # `expected` is the original's current content version; `given` is what the
  # client says it drew on. No version on either side means there is nothing
  # to compare (an unversioned URL). A version that disagrees is a rendering
  # of a picture this file no longer has.
  def source_version_ok?(expected, given) do
    cond do
      not present?(expected) -> true
      not present?(given) -> true
      given == expected -> true
      true -> false
    end
  end

  defp present?(value), do: is_binary(value) and value != ""

  # ── the steps ────────────────────────────────────────────────────────────

  defp require_user(conn) do
    case conn.assigns[:phoenix_kit_current_user] do
      %User{} = user -> {:ok, user}
      _ -> {:error, :unauthorized}
    end
  end

  defp fetch_file(uuid) do
    case Storage.get_file(uuid) do
      %Storage.File{} = file -> {:ok, file}
      _ -> {:error, :not_found}
    end
  end

  defp ensure_image(%Storage.File{file_type: "image"}), do: :ok
  defp ensure_image(%Storage.File{mime_type: "image/" <> _}), do: :ok
  defp ensure_image(_), do: {:error, :not_image}

  defp authorize(%User{} = user, file) do
    if allowed?(file, user, Scope.for_user(user)), do: :ok, else: {:error, :forbidden}
  end

  defp extract_image(%{"image" => %Plug.Upload{} = upload}), do: {:ok, upload}
  defp extract_image(_), do: {:error, :no_file}

  defp readable_size(%Plug.Upload{path: path} = upload) do
    case File.stat(path) do
      {:ok, %{size: size}} when size > 0 and size <= @max_bytes -> {:ok, upload}
      {:ok, %{size: size}} when size > @max_bytes -> {:error, :too_large}
      _ -> {:error, :no_file}
    end
  end

  defp accept_magic(%Plug.Upload{path: path}) do
    with {:ok, header} <- File.open(path, [:read, :binary], &IO.binread(&1, 16)),
         true <- image_magic?(header) do
      :ok
    else
      false -> {:error, :bad_type}
      _ -> {:error, :no_file}
    end
  end

  defp bind_original(file, params) do
    case Storage.get_file_instance_by_name(file.uuid, "original") do
      %Storage.FileInstance{file_name: key} = instance ->
        if source_version_ok?(URLSigner.version(instance), params["source_version"]),
          do: {:ok, key},
          else: {:error, :stale_source}

      _ ->
        {:error, :not_found}
    end
  end

  # Decode the untrusted bytes ONCE, under ImageMagick resource limits and a
  # pixel budget, into a trusted file no larger than the biggest slot asked
  # for. Each slot is then a resize of that trusted file.
  defp write_variants(file, %Plug.Upload{path: path}, variants, source_key, params) do
    case prepare_burn(file, path, variants, params) do
      {:ok, safe, format} ->
        try do
          commit_variants(file, safe, format, variants, source_key)
        after
          File.rm(safe)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp prepare_burn(file, path, variants, params) do
    edge = variants |> Enum.map(&variant_long_edge/1) |> Enum.max()

    case {burn_format_for(file.mime_type), layout_from_params(params)} do
      {"gif", {:ok, layout}} -> prepare_animation(file, path, edge, layout)
      # A GIF burned by a client that sent the whole picture (no layout) is
      # kept as the still it is.
      {"gif", _} -> prepare_still(file, path, edge, "png")
      {format, _} -> prepare_still(file, path, edge, format)
    end
  end

  defp prepare_still(file, path, edge, format) do
    safe = temp_path("safe", format)

    case ImageProcessor.sanitize(path, safe, max_edge: edge, quality: 90, format: format) do
      {:ok, _} ->
        {:ok, safe, format}

      {:error, reason} ->
        File.rm(safe)
        Logger.warning("burn sanitize failed for #{file.uuid}: #{inspect(reason)}")
        {:error, :convert_failed}
    end
  end

  # The upload is the markup alone, on a transparent canvas; the frames come
  # from the stored original. Sanitized like any upload (it may come back
  # smaller than it was sent, so the layout is scaled to what it became),
  # then laid over every frame.
  defp prepare_animation(file, path, edge, layout) do
    overlay = temp_path("overlay", "png")
    safe = temp_path("safe", "gif")

    result =
      with {:ok, _} <-
             ImageProcessor.sanitize(path, overlay, max_edge: edge, quality: 90, format: "png"),
           {:ok, {ow, oh}} <- ImageProcessor.extract_dimensions(overlay),
           layout = scale_layout(layout, ow, oh),
           {:ok, original, _file, _source} <- Storage.retrieve_original(file.uuid) do
        try do
          compose_frames(original, overlay, safe, layout)
        after
          File.rm(original)
        end
      end

    File.rm(overlay)

    case result do
      {:ok, format} ->
        {:ok, safe, format}

      {:error, reason} ->
        File.rm(safe)
        Logger.warning("burn animation failed for #{file.uuid}: #{inspect(reason)}")
        {:error, :convert_failed}
    end
  end

  # Every frame, or — for an animation too large to re-encode — the first
  # one, kept as a still PNG rather than no burn at all.
  defp compose_frames(original, overlay, safe, layout) do
    case ImageProcessor.composite_animation(original, overlay, safe, layout) do
      {:ok, _} ->
        {:ok, "gif"}

      {:error, :too_large} ->
        with {:ok, _} <-
               ImageProcessor.composite_animation(original, overlay, safe, layout, still: true),
             do: {:ok, "png"}

      {:error, _} = error ->
        error
    end
  end

  @doc false
  # Where the picture sits in the burn the client drew, in that burn's
  # pixels: `canvas_w`×`canvas_h` overall, the picture at `picture_x`,
  # `picture_y`, `picture_w`×`picture_h`. Only an animated burn needs it.
  def layout_from_params(params) do
    keys = ~w(canvas_w canvas_h picture_x picture_y picture_w picture_h)

    with [cw, ch, x, y, w, h] = nums <- Enum.map(keys, &layout_number(params[&1])),
         true <- Enum.all?(nums, &is_float/1),
         true <- Enum.all?([cw, ch, w, h], &(&1 >= 1 and &1 <= 16_000)),
         true <- Enum.all?([x, y], &(abs(&1) <= 16_000)) do
      {:ok, %{canvas_w: cw, canvas_h: ch, x: x, y: y, w: w, h: h}}
    else
      _ -> :error
    end
  end

  # A number the client sent, or nil — never a float it did not send. A
  # nested param (`canvas_w[a]=1`) arrives as a map and is no number.
  defp layout_number(value) when is_binary(value) do
    case Float.parse(value) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp layout_number(_), do: nil

  @doc false
  # The layout carried into the overlay's real size, in whole pixels.
  def scale_layout(%{canvas_w: cw, canvas_h: ch} = l, ow, oh) do
    kx = ow / cw
    ky = oh / ch

    %{
      canvas_w: ow,
      canvas_h: oh,
      x: round(l.x * kx),
      y: round(l.y * ky),
      w: max(1, round(l.w * kx)),
      h: max(1, round(l.h * ky))
    }
  end

  defp commit_variants(file, safe, format, variants, source_key) do
    written =
      Enum.reduce_while(variants, [], fn variant, acc ->
        case write_variant(file, safe, format, variant, source_key) do
          {:ok, instance} ->
            {:cont,
             [
               %{
                 variant: variant,
                 width: instance.width,
                 height: instance.height,
                 size: instance.size,
                 url:
                   URLSigner.signed_url(file.uuid, variant,
                     version: instance,
                     locale: :none,
                     private: Libraries.private_file?(file)
                   )
               }
               | acc
             ]}

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
      end)

    case written do
      {:error, reason} ->
        {:error, reason}

      list ->
        {:ok, Enum.reverse(list)}
    end
  end

  defp write_variant(file, safe, format, variant, source_key) do
    {w, h} = variant_box(variant)
    out = temp_path(variant, format)
    {ext, mime} = ext_mime(format)

    result =
      case ImageProcessor.resize(safe, out, w, h,
             quality: 90,
             format: ext,
             animated: format == "gif"
           ) do
        {:ok, _} ->
          VariantGenerator.store_prepared_variant(file, variant, out, ext, mime,
            source_key: source_key
          )

        {:error, reason} ->
          Logger.warning("burn resize failed for #{file.uuid}/#{variant}: #{inspect(reason)}")
          {:error, :convert_failed}
      end

    File.rm(out)
    result
  end

  defp variant_long_edge(variant) do
    {w, h} = variant_box(variant)
    max(w, h)
  end

  # Neither burn is a configured dimension — they exist so cards and the
  # viewer can show the markup without displacing `small`, which the editor
  # uses as its first paint.
  @doc false
  def variant_box("burned"), do: {@burned_edge, @burned_edge}
  def variant_box("burned_large"), do: {@burned_large_edge, @burned_large_edge}

  def variant_box(variant) do
    Storage.list_dimensions()
    |> Enum.find(&(&1.name == variant))
    |> case do
      %{width: w, height: h} when is_integer(w) and is_integer(h) and w > 0 and h > 0 ->
        {w, h}

      _ ->
        {150, 150}
    end
  end

  # What the drawing WAS when this burn was made, as the client saw it.
  #
  # The viewer hands it back on the next open, and a client whose drawing
  # already hashes to it knows there is nothing to render — which is the
  # difference between burning once per change and burning once per visit.
  # A burn is seconds of compose and an upload of a few MB, and most visits
  # to a file change nothing about its markup.
  #
  # The client owns the hash: both sides of the comparison are then the same
  # code reading the same in-memory shapes, rather than two descriptions of a
  # drawing that have to agree. This side only stores it.
  @doc false
  def remember_fingerprint(_file, fingerprint)
      when not is_binary(fingerprint) or byte_size(fingerprint) > @fingerprint_bytes,
      do: :ok

  #
  # Merged into the row as it is NOW (`Storage.update_file_metadata/2`), never
  # written from the `file` loaded at the top of the request: a burn runs for
  # seconds, and `metadata` also holds the rotation, the title/description
  # copy, tags and the EXIF keys. A map built from that stale struct reverted
  # whatever the user changed meanwhile — typically a rotation or a title,
  # right after turning the pencil off.
  def remember_fingerprint(file, fingerprint) do
    note = %{"fingerprint" => fingerprint, "at" => DateTime.utc_now() |> DateTime.to_iso8601()}

    case Storage.update_file_metadata(file, &Map.put(&1, "burn", note)) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        # The pictures are stored; only the note about what they were made
        # from is missing, which costs one needless burn next time.
        Logger.warning("burn fingerprint not recorded for #{file.uuid}: #{inspect(reason)}")
        :ok
    end
  end

  defp temp_path(tag, ext) do
    Path.join(System.tmp_dir!(), "pk_burn_#{tag}_#{System.unique_integer([:positive])}.#{ext}")
  end

  # ── answers ──────────────────────────────────────────────────────────────

  defp fail(conn, reason) do
    {status, code, message} =
      case reason do
        :unauthorized ->
          {:unauthorized, "UNAUTHORIZED", "Sign in first"}

        :forbidden ->
          {:forbidden, "FORBIDDEN", "Not yours to re-render"}

        :not_found ->
          {:not_found, "NOT_FOUND", "No such file"}

        :not_image ->
          {:bad_request, "NOT_IMAGE", "Only a picture can take a burn"}

        :no_file ->
          {:bad_request, "NO_FILE", "Send the picture as `image`"}

        :bad_type ->
          {:bad_request, "BAD_TYPE", "JPEG or PNG only"}

        :bad_variant ->
          {:bad_request, "BAD_VARIANT", "Writable slots: #{Enum.join(@writable, ", ")}"}

        :too_large ->
          {:request_entity_too_large, "TOO_LARGE", "That is larger than a burn gets"}

        :stale_source ->
          {:conflict, "STALE", "The picture changed while this was drawn"}

        _ ->
          {:internal_server_error, "FAILED", "Could not store the rendering"}
      end

    conn |> put_status(status) |> json(%{error: code, message: message})
  end
end
