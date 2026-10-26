defmodule PhoenixKit.Modules.Storage.Hdr do
  @moduledoc """
  Whether a photo carries an HDR **gain map**: the second picture that tells an
  HDR-capable screen how far to push the highlights past normal white. An iPhone
  photo is a normal (SDR) image plus this map; an ordinary renditions pipeline
  (ImageMagick) keeps the first and drops the second, which is why a rendition
  looks flat next to the same photo in Photos.

  `read/1` looks at the file's head only and returns `%{}` for a photo without
  one, else

      %{"gain_map" => true,
        "container" => "jpeg",              # "jpeg", "heic" or "avif"
        "kinds" => ["apple", "iso21496"],   # which descriptions of it the file has
        "headroom" => 4.974161,             # HDR peak as a multiple of SDR white, or nil
        "gain_map_bytes" => 205482,          # the size of the map's picture, or nil
        "parameters" => %{...}}              # a HEIC or AVIF: the file's own, see below

  The kinds:

    * `"iso21496"` — the ISO 21496-1 marker (iPhone 15 and later, Android 15)
    * `"apple"` — Apple's own auxiliary `hdrgainmap` picture and its headroom
    * `"ultrahdr"` — Google's Ultra HDR / Adobe gain map metadata (`hdrgm:`), what
      Android phones write; newer ones write the ISO marker as well

  A JPEG keeps the map as a second picture listed in its Multi-Picture directory;
  a HEIC or AVIF as a `tmap` item (ISO) or Apple's auxiliary picture. Nothing is
  decoded.

  For a HEIC or AVIF with a `tmap` item the box structure is read (`HeifBoxes`) and
  its ISO 21496-1 payload gives `"headroom"` (the alternate headroom, a power of two)
  and `"parameters"`, the gain map's own numbers under the names of Ultra HDR's `hdrgm`
  properties (`"gain_map_min"`, `"gain_map_max"`, `"gamma"`, `"offset_sdr"`,
  `"offset_hdr"`, `"hdr_capacity_min"`, `"hdr_capacity_max"`, all log2 but the gamma
  and the offsets; `"multichannel"` says the map has a value per colour channel).
  """

  alias PhoenixKit.Modules.Storage.HeifBoxes

  # Everything needed lives in the first segments of a JPEG (before the picture's
  # data starts) and in the `meta` box of a HEIF file.
  @head 524_288
  @second_image_read 16_384

  @iso_marker "urn:iso:std:iso:ts:21496:-1"
  @apple_aux "urn:com:apple:photo:2020:aux:hdrgainmap"
  @ultrahdr_ns "http://ns.adobe.com/hdr-gain-map/1.0/"

  @doc "The gain-map summary of the image at `path`, `%{}` when it has none."
  @spec read(Path.t()) :: map()
  def read(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, io} ->
        try do
          io |> head() |> detect(io)
        after
          File.close(io)
        end

      {:error, _} ->
        %{}
    end
  rescue
    _ -> %{}
  end

  @doc "Whether a summary from `read/1` describes a photo with a gain map."
  @spec gain_map?(term()) :: boolean()
  def gain_map?(%{"gain_map" => true}), do: true
  def gain_map?(_), do: false

  defp head(io) do
    case :file.pread(io, 0, @head) do
      {:ok, data} -> data
      _ -> <<>>
    end
  end

  defp detect(<<0xFF, 0xD8, _::binary>> = head, io), do: jpeg(head, io)
  defp detect(<<_size::32, "ftyp", _::binary>>, io), do: heif(io)
  defp detect(_head, _io), do: %{}

  # ── JPEG ──────────────────────────────────────────────────────

  defp jpeg(head, io) do
    segments = segments(head, 2, [])

    xmp =
      for {0xE1, _at, data} <- segments,
          match?(<<"http://ns.adobe.com/xap/1.0/\0", _::binary>>, data),
          do: data

    iso? =
      Enum.any?(segments, fn {m, _, d} -> m == 0xE2 and String.starts_with?(d, @iso_marker) end)

    ultra? = Enum.any?(xmp, &String.contains?(&1, @ultrahdr_ns))

    mpf =
      Enum.find_value(segments, fn
        {0xE2, at, <<"MPF\0", tiff::binary>>} -> mp_images(tiff, at + 4 + 4)
        _ -> nil
      end) || []

    second = mpf |> Enum.at(1) |> inside_file(io)
    info = if second, do: second_picture(io, second), else: nil
    apple = info && info.apple?

    kinds =
      [apple && "apple", iso? && "iso21496", ultra? && "ultrahdr"]
      |> Enum.filter(& &1)

    # A marker alone is not a map: the second picture has to be there.
    if kinds != [] and second != nil do
      %{
        "gain_map" => true,
        "container" => "jpeg",
        "kinds" => kinds,
        "headroom" => info && info.headroom,
        "gain_map_bytes" => second.size
      }
    else
      %{}
    end
  end

  # A directory that lists a picture the file does not hold (a truncated copy) names
  # no map.
  defp inside_file(nil, _io), do: nil

  defp inside_file(%{offset: offset, size: size} = image, io) do
    case :file.position(io, :eof) do
      {:ok, total} when offset > 0 and size > 0 and offset + size <= total ->
        case :file.pread(io, offset, 2) do
          {:ok, <<0xFF, 0xD8>>} -> image
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # `{marker, file_offset_of_segment, payload}` for each marker segment before the
  # picture's data (the SOS marker, or the end of what was read).
  defp segments(data, at, acc) when at + 4 <= byte_size(data) do
    case binary_part(data, at, 4) do
      <<0xFF, marker, len::16>> when marker not in [0xD8, 0xDA, 0xD9] and len >= 2 ->
        if at + 2 + len <= byte_size(data) do
          payload = binary_part(data, at + 4, len - 2)
          segments(data, at + 2 + len, [{marker, at, payload} | acc])
        else
          Enum.reverse(acc)
        end

      _ ->
        Enum.reverse(acc)
    end
  end

  defp segments(_data, _at, acc), do: Enum.reverse(acc)

  # The pictures of a Multi-Picture file: `%{offset, size}` in file offsets.
  # `tiff` starts at the MP header (its byte order mark), which is where the
  # entries' offsets count from; `base` is that header's offset in the file.
  defp mp_images(<<order::binary-size(2), _::binary>> = tiff, base)
       when order in ["II", "MM"] do
    big? = order == "MM"
    ifd = int(tiff, 4, 4, big?)

    # `int/4` always returns an integer (0 when out of range), so only the
    # bound on the IFD itself can fail here.
    if ifd + 2 <= byte_size(tiff) do
      count = int(tiff, ifd, 2, big?)
      entries = for i <- 0..(count - 1)//1, do: binary_part_safe(tiff, ifd + 2 + i * 12, 12)

      case Enum.find(entries, &match_tag?(&1, 0xB002, big?)) do
        nil ->
          []

        <<_tag::16, _type::16, bytes::binary-size(4), off::binary-size(4)>> ->
          n = div(int(bytes, 0, 4, big?), 16)
          list = binary_part_safe(tiff, int(off, 0, 4, big?), n * 16)
          images(list, base, big?, [])
      end
    else
      []
    end
  end

  defp mp_images(_tiff, _base), do: []

  defp images(
         <<_attr::binary-size(4), size::binary-size(4), off::binary-size(4), _dep::binary-size(4),
           rest::binary>>,
         base,
         big?,
         acc
       ) do
    s = int(size, 0, 4, big?)
    o = int(off, 0, 4, big?)
    # The first picture's offset is 0 (it is the file itself); the others count
    # from the MP header.
    at = if acc == [], do: 0, else: base + o
    images(rest, base, big?, acc ++ [%{offset: at, size: s}])
  end

  defp images(_rest, _base, _big?, acc), do: acc

  defp match_tag?(<<tag::binary-size(2), _::binary>>, wanted, big?),
    do: int(tag, 0, 2, big?) == wanted

  defp match_tag?(_other, _wanted, _big?), do: false

  defp int(bin, at, len, big?) when at >= 0 and at + len <= byte_size(bin) do
    bits = len * 8
    <<n::integer-size(bits)>> = binary_part(bin, at, len)
    if big?, do: n, else: swap(n, len)
  end

  defp int(_bin, _at, _len, _big?), do: 0

  # `n` was read big-endian; reinterpret the same bytes little-endian.
  defp swap(n, len) do
    bits = len * 8
    <<m::little-integer-size(bits)>> = <<n::integer-size(bits)>>
    m
  end

  defp binary_part_safe(bin, at, len) when at >= 0 and at + len <= byte_size(bin),
    do: binary_part(bin, at, len)

  defp binary_part_safe(_bin, _at, _len), do: <<>>

  # What the second picture's XMP says. Apple's map announces itself there and
  # gives its headroom as a ratio of peak to SDR white; an Android Ultra HDR map
  # gives `HDRCapacityMax` as a power of two (log2 of the same ratio), so it is
  # turned into a ratio to be comparable.
  defp second_picture(io, %{offset: offset}) do
    case :file.pread(io, offset, @second_image_read) do
      {:ok, data} ->
        %{
          apple?: String.contains?(data, @apple_aux),
          headroom: apple_headroom(data) || ultra_headroom(data)
        }

      _ ->
        %{apple?: false, headroom: nil}
    end
  end

  defp apple_headroom(data),
    do: number(data, ~r/<HDRGainMap:HDRGainMapHeadroom>\s*([-+0-9.eE]+)\s*</)

  defp ultra_headroom(data) do
    case number(data, ~r/hdrgm:HDRCapacityMax(?:="|>)\s*([-+0-9.eE]+)/) do
      nil -> nil
      stops -> :math.pow(2, stops)
    end
  end

  defp number(data, regex) do
    with [_, text] <- Regex.run(regex, data),
         {value, _} <- Float.parse(text) do
      value
    else
      _ -> nil
    end
  end

  # ── HEIF / AVIF ───────────────────────────────────────────────

  # An ISO gain map is an item of type `tmap`, whose payload holds the parameters
  # (ISO 21496-1); Apple's is an auxiliary picture named by a URN. Both are in the
  # `meta` box, which `HeifBoxes` reads whole whatever its size.
  defp heif(io) do
    case HeifBoxes.read(io) do
      {:ok, heif} -> heif_summary(io, heif)
      {:error, _} -> %{}
    end
  end

  defp heif_summary(io, heif) do
    iso? = HeifBoxes.item_of_type?(heif, "tmap")
    apple? = String.contains?(heif.meta, @apple_aux)
    kinds = [apple? && "apple", iso? && "iso21496"] |> Enum.filter(& &1)

    if kinds == [] do
      %{}
    else
      tone_map = if iso?, do: tone_map(io, heif)

      %{
        "gain_map" => true,
        "container" => container(heif.brand),
        "kinds" => kinds,
        "headroom" => tone_map && :math.pow(2, tone_map.params.alternate_headroom),
        "gain_map_bytes" => gain_map_bytes(heif, tone_map)
      }
      |> put_parameters(tone_map)
    end
  end

  defp tone_map(io, heif) do
    case HeifBoxes.gain_map(io, heif) do
      {:ok, tone_map} -> tone_map
      _ -> nil
    end
  end

  # The size of the map's picture: the one the `tmap` item combines with the photo, or
  # Apple's auxiliary picture.
  defp gain_map_bytes(heif, %{gain_map: id}), do: HeifBoxes.item_size(heif, id)

  defp gain_map_bytes(heif, nil) do
    heif.items
    |> Map.keys()
    |> Enum.find(fn id ->
      Enum.any?(HeifBoxes.properties_of(heif, id), fn {type, payload} ->
        type == "auxC" and String.contains?(payload, @apple_aux)
      end)
    end)
    |> case do
      nil -> nil
      id -> HeifBoxes.item_size(heif, id)
    end
  end

  # The parameters the file states, in the names of Ultra HDR's `hdrgm` properties
  # (all log2 but the gamma and the offsets).
  defp put_parameters(summary, %{params: params}) do
    Map.put(summary, "parameters", %{
      "gain_map_min" => params.gain_map_min,
      "gain_map_max" => params.gain_map_max,
      "gamma" => params.gamma,
      "offset_sdr" => params.base_offset,
      "offset_hdr" => params.alternate_offset,
      "hdr_capacity_min" => params.base_headroom,
      "hdr_capacity_max" => params.alternate_headroom,
      "multichannel" => params.multichannel?
    })
  end

  defp put_parameters(summary, nil), do: summary

  # HEIF is the box structure; the file's major brand says whether it is an AVIF.
  defp container(brand) when brand in ["avif", "avis"], do: "avif"
  defp container(_brand), do: "heic"
end
