defmodule PhoenixKit.Modules.Storage.HdrResize do
  @moduledoc """
  Makes a smaller copy of a gain-map JPEG that is still an HDR photo.

  An iPhone or Pixel JPEG is two JPEGs in one file: the picture (SDR) and a small
  **gain map** that says how much brighter each part is on an HDR screen, tied
  together by a Multi-Picture directory (and, for Android, a line of XMP naming the
  map's length). A plain resize keeps the picture and loses the map; this keeps both:

    1. the file is split into the picture and the gain map (`Hdr`'s directory);
    2. each is resized with ImageMagick (`ImageProcessor.resize/5`: pinned input,
       resource limits, a pixel budget), the map by the same ratio as the picture;
    3. the metadata that describes the pictures (colour profile, EXIF, the XMP and
       ISO 21496-1 parameters of the map) is carried over **unchanged**, because it
       is about brightness and colour, not size. With `strip_metadata: true` the EXIF
       (device, time, position, maker notes) is dropped but for the orientation tag,
       and only the gain-map properties are kept in either picture's XMP;
    4. what *is* about size is rewritten: the directory's sizes and offsets, and the
       map's byte length in the picture's XMP.

  Nothing is decoded to HDR pixels, so nothing is tone-mapped or clipped: the map
  is the camera's own.

  Only JPEGs whose map is a second picture are handled (`{:error, :no_gain_map}`
  otherwise; a HEIC or AVIF gain map is a different container, see `HeifHdr`). Anything that does not
  parse as expected is an `{:error, _}`, and the caller keeps its ordinary SDR
  rendition: an HDR rendition is a bonus, never a reason for a size to be missing.
  """

  require Logger

  alias PhoenixKit.Modules.Storage.HdrXmp
  alias PhoenixKit.Modules.Storage.ImageProcessor

  # The gain map is detail the eye does not see, but its precision is brightness.
  @gain_map_quality 90

  @type result ::
          {:ok, %{width: pos_integer(), height: pos_integer(), gain_map_bytes: pos_integer()}}

  @doc """
  Writes a copy of the gain-map JPEG at `source` to `dest`, `width` pixels wide
  (never larger than the source), at JPEG `:quality` (default 85).

  Width and the returned dimensions are measured as displayed, after EXIF
  orientation. The stored pixels retain the camera's orientation tag.
  """
  @spec resize(Path.t(), Path.t(), pos_integer(), keyword()) :: result() | {:error, term()}
  def resize(source, dest, width, opts \\ []) do
    quality = Keyword.get(opts, :quality, 85)
    strip? = Keyword.get(opts, :strip_metadata, false)

    with {:ok, bin} <- File.read(source),
         {:ok, parts} <- split(bin),
         {:ok, {src_w, src_h}} <- sof_dims(parts.primary),
         {:ok, {gm_w, gm_h}} <- sof_dims(parts.gain),
         orientation = orientation(parts),
         box = width_box(width, {src_w, src_h}, orientation),
         {:ok, primary_core} <- resized_core(parts.primary, box, quality),
         {:ok, {out_w, out_h}} <- sof_dims(primary_core),
         gm_target =
           if(orientation in 5..8,
             do: {nil, max(round(gm_h * out_h / src_h), 1)},
             else: {max(round(gm_w * out_w / src_w), 1), nil}
           ),
         {:ok, gain_core} <- resized_core(parts.gain, gm_target, @gain_map_quality) do
      {shown_out_w, shown_out_h} = shown_size({out_w, out_h}, orientation)
      gain = assemble_gain(parts.gain_segments, gain_core, strip?)
      primary = assemble_primary(parts, primary_core, byte_size(gain), strip?)

      case File.write(dest, primary <> gain) do
        :ok ->
          {:ok, %{width: shown_out_w, height: shown_out_h, gain_map_bytes: byte_size(gain)}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  @doc """
  Writes a `width` x `height` crop of the gain-map JPEG at `source` to `dest`, still an
  HDR photo: the picture is cropped, and the gain map is cropped to the same part of
  it (a map covers the whole picture, so cutting the picture alone would put the
  brightness of one place over another).

  The box is cut as `ImageProcessor.resize_and_crop_focus/6` cuts it: the largest
  window of its shape, centered on `:focal` (`{x, y}`, fractions of the photo as it
  is displayed; the middle by default) as far as the edges allow, then scaled to the
  box, which shrinks to fit when the photo is smaller. A turned photo (EXIF
  orientation) is cut where it is shown, and keeps its orientation tag, so its pixels
  and its map stay as the camera stored them. Takes `:quality` and `:strip_metadata`
  like `resize/4`.
  """
  @spec crop(Path.t(), Path.t(), {pos_integer(), pos_integer()}, keyword()) ::
          result() | {:error, term()}
  def crop(source, dest, {width, height}, opts \\ []) do
    quality = Keyword.get(opts, :quality, 85)
    strip? = Keyword.get(opts, :strip_metadata, false)
    focal = Keyword.get(opts, :focal) || {0.5, 0.5}

    with {:ok, bin} <- File.read(source),
         {:ok, parts} <- split(bin),
         {:ok, {src_w, src_h}} <- sof_dims(parts.primary),
         {:ok, {gm_w, gm_h}} <- sof_dims(parts.gain),
         orientation = orientation(parts),
         shown = shown_size({src_w, src_h}, orientation),
         box = ImageProcessor.cap_to_original({width, height}, shown),
         window = ImageProcessor.focus_window(focal, shown, box),
         {cw, ch, left, top} = stored_window(window, {src_w, src_h}, orientation),
         {out_w, out_h} = stored_box(box, orientation),
         {:ok, primary_core} <-
           cropped_core(parts.primary, {cw, ch, left, top}, {out_w, out_h}, quality),
         gain_window = scale_window({cw, ch, left, top}, {src_w, src_h}, {gm_w, gm_h}),
         gain_box =
           {max(round(out_w * gm_w / src_w), 1), max(round(out_h * gm_h / src_h), 1)},
         {:ok, gain_core} <- cropped_core(parts.gain, gain_window, gain_box, @gain_map_quality) do
      gain = assemble_gain(parts.gain_segments, gain_core, strip?)
      primary = assemble_primary(parts, primary_core, byte_size(gain), strip?)

      case File.write(dest, primary <> gain) do
        :ok ->
          {:ok, %{width: elem(box, 0), height: elem(box, 1), gain_map_bytes: byte_size(gain)}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  # ── orientation ───────────────────────────────────────────────

  # How the picture is turned for display (EXIF orientation 1..8; 1 when it has no tag).
  defp orientation(parts) do
    parts.segments
    |> Enum.find_value(fn
      %{marker: 0xE1, payload: <<"Exif\0\0", tiff::binary>>} -> exif_orientation(tiff)
      _ -> nil
    end)
    |> case do
      n when n in 1..8 -> n
      _ -> 1
    end
  end

  # Orientations 5..8 turn the picture a quarter, so it is shown with its sides swapped.
  defp shown_size({w, h}, n) when n in 5..8, do: {h, w}
  defp shown_size(size, _), do: size

  # Display width is stored height for a quarter turn. Resize that axis
  # directly so a thin photo cannot round its other target axis down to zero.
  defp width_box(width, {_w, h}, n) when n in 5..8, do: {nil, min(width, h)}
  defp width_box(width, {w, _h}, _n), do: {min(width, w), nil}

  defp stored_box({w, h}, n) when n in 5..8, do: {h, w}
  defp stored_box(box, _), do: box

  # The window `{width, height, left, top}` as seen on screen, found in the picture as
  # it is stored: each orientation's inverse, on the window's edges (`x0..x1`, `y0..y1`
  # on screen) against the stored `sw` x `sh`.
  defp stored_window({w, h, left, top}, {sw, sh}, n) do
    {x0, x1, y0, y1} = {left, left + w, top, top + h}

    {sx0, sx1, sy0, sy1} =
      case n do
        2 -> {sw - x1, sw - x0, y0, y1}
        3 -> {sw - x1, sw - x0, sh - y1, sh - y0}
        4 -> {x0, x1, sh - y1, sh - y0}
        5 -> {y0, y1, x0, x1}
        6 -> {y0, y1, sh - x1, sh - x0}
        7 -> {sw - y1, sw - y0, sh - x1, sh - x0}
        8 -> {sw - y1, sw - y0, x0, x1}
        _ -> {x0, x1, y0, y1}
      end

    {sx1 - sx0, sy1 - sy0, sx0, sy0}
  end

  # The same part of the picture in another picture of the same scene (the gain map
  # is a fraction of the picture's size), kept inside it and at least a pixel.
  @doc false
  def scale_window({w, h, left, top}, {pw, ph}, {gw, gh}) do
    x0 = min(round(left * gw / pw), gw - 1)
    x1 = min(max(round((left + w) * gw / pw), x0 + 1), gw)
    y0 = min(round(top * gh / ph), gh - 1)
    y1 = min(max(round((top + h) * gh / ph), y0 + 1), gh)

    {x1 - x0, y1 - y0, x0, y0}
  end

  # `bin` cropped to `window` and scaled to `box`, as the JPEG image data alone.
  defp cropped_core(bin, window, box, quality) do
    input = temp(".jpg")
    output = temp(".jpg")

    try do
      with :ok <- File.write(input, bin),
           {:ok, _} <- ImageProcessor.crop_window(input, output, window, box, quality: quality),
           {:ok, out} <- File.read(output) do
        {_segments, core_at} = segments(out)
        {:ok, binary_part(out, core_at, byte_size(out) - core_at)}
      end
    after
      File.rm(input)
      File.rm(output)
    end
  end

  # ── splitting ─────────────────────────────────────────────────

  @doc false
  # The picture and the gain map of `bin`, each with its marker segments (before the
  # image data) and the MP directory's description of them.
  def split(<<0xFF, 0xD8, _::binary>> = bin) do
    {segments, _core_at} = segments(bin)

    with %{} = mpf <- Enum.find(segments, &mpf?/1),
         {:ok, order, entries} <- mp_entries(mpf, byte_size(bin)),
         [first, second | _] <- entries do
      primary = binary_part(bin, 0, second.at)
      gain = binary_part(bin, second.at, min(second.size, byte_size(bin) - second.at))
      {gain_segments, _} = segments(gain)

      {:ok,
       %{
         primary: primary,
         gain: gain,
         segments: segments,
         gain_segments: gain_segments,
         order: order,
         attrs: {first.attr, second.attr},
         deps: {first.dep, second.dep}
       }}
    else
      _ -> {:error, :no_gain_map}
    end
  end

  def split(_), do: {:error, :not_a_jpeg}

  # `[%{marker, at, raw, payload}]` for the marker segments that open a JPEG (up to
  # the first that is not an APPn or comment), and where its image data starts.
  @doc false
  def segments(bin), do: segments(bin, 2, [])

  defp segments(bin, at, acc) when at + 4 <= byte_size(bin) do
    case binary_part(bin, at, 4) do
      <<0xFF, marker, len::16>> when (marker in 0xE0..0xEF or marker == 0xFE) and len >= 2 ->
        if at + 2 + len <= byte_size(bin) do
          raw = binary_part(bin, at, 2 + len)
          <<_::binary-size(4), payload::binary>> = raw

          segments(bin, at + 2 + len, [
            %{marker: marker, at: at, raw: raw, payload: payload} | acc
          ])
        else
          {Enum.reverse(acc), at}
        end

      _ ->
        {Enum.reverse(acc), at}
    end
  end

  defp segments(_bin, at, acc), do: {Enum.reverse(acc), at}

  defp mpf?(%{marker: 0xE2, payload: <<"MPF\0", _::binary>>}), do: true
  defp mpf?(_), do: false

  # The pictures an MP directory lists: `%{attr, size, at, dep}` with `at` a file offset.
  defp mp_entries(%{at: seg_at, payload: <<"MPF\0", tiff::binary>>}, file_size) do
    case tiff do
      <<order::binary-size(2), _::binary>> when order in ["II", "MM"] ->
        mp_entries(tiff, order, seg_at + 8, file_size)

      _ ->
        :error
    end
  rescue
    _ -> :error
  end

  defp mp_entries(tiff, order, base, file_size) do
    big? = order == "MM"
    ifd = int(tiff, 4, 4, big?)
    count = int(tiff, ifd, 2, big?)
    tags = for i <- 0..(count - 1)//1, do: binary_part(tiff, ifd + 2 + i * 12, 12)

    case Enum.find(tags, &(int(&1, 0, 2, big?) == 0xB002)) do
      nil ->
        :error

      tag ->
        list = binary_part(tiff, int(tag, 8, 4, big?), int(tag, 4, 4, big?))

        entries =
          for <<attr::binary-size(4), size::binary-size(4), off::binary-size(4),
                dep::binary-size(4) <- list>> do
            offset = int(off, 0, 4, big?)

            %{
              attr: attr,
              size: int(size, 0, 4, big?),
              at: if(offset == 0, do: 0, else: base + offset),
              dep: dep
            }
          end

        if Enum.all?(entries, &(&1.at + &1.size <= file_size)),
          do: {:ok, order, entries},
          else: :error
    end
  end

  defp int(bin, at, len, big?) do
    bits = len * 8
    chunk = binary_part(bin, at, len)

    if big? do
      <<n::big-integer-size(bits)>> = chunk
      n
    else
      <<n::little-integer-size(bits)>> = chunk
      n
    end
  end

  defp put_int(n, len, true), do: <<n::big-integer-size(len * 8)>>
  defp put_int(n, len, false), do: <<n::little-integer-size(len * 8)>>

  # ── image dimensions, from the SOF marker ─────────────────────

  @sof Enum.to_list(0xC0..0xCF) -- [0xC4, 0xC8, 0xCC]

  # A whole JPEG, or its image data alone (from the first table on).
  defp sof_dims(<<0xFF, 0xD8, rest::binary>>), do: sof_dims(rest, 0)
  defp sof_dims(<<0xFF, _marker, _::binary>> = core), do: sof_dims(core, 0)
  defp sof_dims(_), do: {:error, :not_a_jpeg}

  defp sof_dims(<<0xFF, marker, len::16, body::binary>>, guard) when guard < 200 do
    cond do
      marker in @sof ->
        case body do
          <<_precision, h::16, w::16, _::binary>> when w > 0 and h > 0 -> {:ok, {w, h}}
          _ -> {:error, :no_dimensions}
        end

      marker in [0xDA, 0xD9] ->
        {:error, :no_dimensions}

      len >= 2 and byte_size(body) >= len - 2 ->
        <<_::binary-size(len - 2), rest::binary>> = body
        sof_dims(rest, guard + 1)

      true ->
        {:error, :no_dimensions}
    end
  end

  defp sof_dims(_bin, _guard), do: {:error, :no_dimensions}

  # ── resizing ──────────────────────────────────────────────────

  # `bin` resized along the requested axis, as JPEG image data alone (from its first DQT on):
  # ImageMagick's own marker segments are not wanted, the originals are carried over.
  defp resized_core(bin, {width, height}, quality) do
    input = temp(".jpg")
    output = temp(".jpg")

    try do
      with :ok <- File.write(input, bin),
           {:ok, _} <-
             ImageProcessor.resize(input, output, width, height, quality: quality, format: "jpg"),
           {:ok, out} <- File.read(output) do
        {_segments, core_at} = segments(out)
        {:ok, binary_part(out, core_at, byte_size(out) - core_at)}
      end
    after
      File.rm(input)
      File.rm(output)
    end
  end

  defp temp(ext) do
    Path.join(
      System.tmp_dir!(),
      "pk_hdr_#{System.unique_integer([:positive])}_#{:erlang.phash2(make_ref())}#{ext}"
    )
  end

  # ── reassembly ────────────────────────────────────────────────

  @xmp "http://ns.adobe.com/xap/1.0/\0"
  @xmp_extension "http://ns.adobe.com/xmp/extension/\0"

  # The gain map: its own segments (parameters, ISO marker) and the resized image.
  @doc false
  def assemble_gain(segments, core, strip?) do
    kept =
      segments
      |> Enum.reject(&mpf?/1)
      |> Enum.flat_map(&keep_gain_segment(&1, strip?))

    IO.iodata_to_binary([<<0xFF, 0xD8>>, kept, core])
  end

  defp keep_gain_segment(%{marker: 0xE1, payload: <<@xmp, _::binary>>} = segment, strip?),
    do: keep_segment(segment, nil, strip?)

  defp keep_gain_segment(segment, true), do: keep_segment(segment, nil, true)
  defp keep_gain_segment(%{raw: raw}, false), do: [raw]

  # The picture: what describes it (kept), the XMP's map length (rewritten), and the
  # directory (rewritten for the new sizes), then the resized image.
  @doc false
  def assemble_primary(parts, core, gain_len, strip?) do
    # The directory is a fixed size, so everything before it can be laid out first,
    # then its offsets are known.
    layout =
      parts.segments
      |> Enum.flat_map(&keep_segment(&1, gain_len, strip?))

    {before_mpf, after_mpf} = Enum.split_while(layout, &(&1 != :mpf))
    [:mpf | after_mpf] = after_mpf ++ []

    head = IO.iodata_to_binary([<<0xFF, 0xD8>>, before_mpf])
    placeholder = mpf_segment(parts, 0, 0, 0)
    tail = IO.iodata_to_binary([after_mpf, core])
    total = byte_size(head) + byte_size(placeholder) + byte_size(tail)
    # The directory's offsets count from its own byte-order mark.
    base = byte_size(head) + 8

    head <> mpf_segment(parts, total, gain_len, total - base) <> tail
  end

  defp keep_segment(%{marker: 0xE0, raw: raw}, _, _), do: [raw]

  # The camera's EXIF (the device, the time, the position, maker notes) goes when the
  # rendition drops metadata; the orientation is not the camera's secret, it is how to
  # show the picture, so that one tag stays.
  defp keep_segment(%{marker: 0xE1, payload: <<"Exif\0\0", tiff::binary>>}, _, true),
    do: orientation_exif(tiff)

  defp keep_segment(%{marker: 0xE1, payload: <<"Exif\0\0", _::binary>>, raw: raw}, _, _),
    do: [raw]

  defp keep_segment(%{marker: 0xE1, payload: <<@xmp_extension, _::binary>>}, _, _), do: []

  defp keep_segment(%{marker: 0xE1, payload: <<@xmp, xml::binary>>}, gain_len, strip?),
    do: [xmp_segment(xml, gain_len, strip?)]

  defp keep_segment(%{marker: 0xE2, payload: <<"ICC_PROFILE\0", _::binary>>, raw: raw}, _, _),
    do: [raw]

  defp keep_segment(
         %{marker: 0xE2, payload: <<"urn:iso:std:iso:ts:21496", _::binary>>, raw: raw},
         _,
         _
       ),
       do: [raw]

  defp keep_segment(%{marker: 0xE2, payload: <<"MPF\0", _::binary>>}, _, _), do: [:mpf]
  defp keep_segment(_other, _, _), do: []

  # An EXIF segment holding the orientation tag and nothing else, when the photo is
  # turned (2..8); none when it is upright or the tag cannot be read.
  defp orientation_exif(tiff) do
    case exif_orientation(tiff) do
      n when n in 2..8 ->
        body =
          <<"Exif\0\0", "MM", 42::16, 8::32, 1::16, 0x0112::16, 3::16, 1::32, n::16, 0::16,
            0::32>>

        [<<0xFF, 0xE1, byte_size(body) + 2::16, body::binary>>]

      _ ->
        []
    end
  end

  @doc false
  def exif_orientation(<<order::binary-size(2), _::binary>> = tiff) when order in ["II", "MM"] do
    big? = order == "MM"
    <<_::binary-size(4), ifd_at::binary-size(4), _::binary>> = tiff

    at =
      if big?,
        do: :binary.decode_unsigned(ifd_at, :big),
        else: :binary.decode_unsigned(ifd_at, :little)

    with true <- at + 2 <= byte_size(tiff),
         <<_::binary-size(at), count::binary-size(2), entries::binary>> <- tiff do
      n = :binary.decode_unsigned(count, if(big?, do: :big, else: :little))
      find_orientation(entries, n, big?)
    else
      _ -> nil
    end
  end

  def exif_orientation(_), do: nil

  defp find_orientation(_, 0, _), do: nil

  defp find_orientation(
         <<tag::binary-size(2), _type::binary-size(2), _count::binary-size(4),
           value::binary-size(2), _::binary-size(2), rest::binary>>,
         left,
         big?
       ) do
    endian = if big?, do: :big, else: :little

    if :binary.decode_unsigned(tag, endian) == 0x0112,
      do: :binary.decode_unsigned(value, endian),
      else: find_orientation(rest, left - 1, big?)
  end

  defp find_orientation(_, _, _), do: nil

  # The picture's XMP, with the gain map's length corrected, and the pointer to an
  # extended XMP (a packet of further metadata that is not carried over) removed.
  defp xmp_segment(xml, gain_len, strip?) do
    payload = @xmp <> HdrXmp.rewrite(xml, gain_len, strip?)

    # XML escaping can make the rewritten packet larger than its input. Refuse
    # it rather than truncating the JPEG segment's 16-bit length on reassembly.
    if byte_size(payload) > 65_533,
      do: raise(ArgumentError, "HDR XMP exceeds the JPEG segment limit")

    <<0xFF, 0xE1, byte_size(payload) + 2::16, payload::binary>>
  end

  # The Multi-Picture directory for two pictures: the picture (`total` bytes, at 0)
  # and the gain map (`gain_len` bytes, `gain_offset` from the directory), in the
  # byte order the original used.
  defp mpf_segment(parts, total, gain_len, gain_offset) do
    big? = parts.order == "MM"
    {attr1, attr2} = parts.attrs
    {dep1, dep2} = parts.deps

    ifd =
      put_int(3, 2, big?) <>
        tag(0xB000, 7, 4, "0100", big?) <>
        tag(0xB001, 4, 1, put_int(2, 4, big?), big?) <>
        tag(0xB002, 7, 32, put_int(50, 4, big?), big?) <>
        put_int(0, 4, big?)

    entries =
      attr1 <>
        put_int(total, 4, big?) <>
        put_int(0, 4, big?) <>
        dep1 <>
        attr2 <> put_int(gain_len, 4, big?) <> put_int(gain_offset, 4, big?) <> dep2

    payload =
      "MPF\0" <> parts.order <> put_int(0x2A, 2, big?) <> put_int(8, 4, big?) <> ifd <> entries

    <<0xFF, 0xE2, byte_size(payload) + 2::16, payload::binary>>
  end

  defp tag(id, type, count, value, big?),
    do: put_int(id, 2, big?) <> put_int(type, 2, big?) <> put_int(count, 4, big?) <> value
end
