defmodule PhoenixKit.Modules.Storage.HeifHdr do
  @moduledoc """
  Makes a smaller copy of a HEIC or AVIF photo with an HDR gain map that is still an
  HDR photo: an Ultra HDR JPEG (the picture, a grey gain-map JPEG and a Multi-Picture
  directory), the form `HdrResize` writes for a JPEG source and `Hdr.read/1` reports as
  a gain map.

  An iPhone photo is a HEIC: the SDR picture, a gain map (a grid of tiles at half the
  size) and a `tmap` item whose ISO 21496-1 payload says how to apply the map. Android
  writes the same `tmap` into an AVIF or HEIC. The pieces are put together like this:

    1. the boxes are read (`HeifBoxes`) for the `tmap` item: which two pictures it
       combines and its parameters (gain-map limits, gamma, offsets, headroom). They
       are log2 quantities with the meaning of Ultra HDR's `hdrgm` properties, so they
       go across as they are;
    2. the picture is read, cut and resized by ImageMagick (`ImageProcessor`: pinned
       input, resource limits, a pixel budget), as for any HEIC;
    3. the gain map is decoded by `ffmpeg` (7.1 or later), which composes a tile grid
       only when the stream group is a filter input, then cut and resized by the same
       fractions of the picture's size;
    4. both are written as JPEGs and assembled by `HdrResize`'s writer: the picture with
       its colour profile, an XMP packet naming the map, and the directory; the map with
       the `hdrgm` XMP.

  Nothing is tone-mapped: the map is the camera's own. A HEIC is turned for display
  by the decoders of both pictures (`irot`), so the picture and the map come out
  upright and aligned; a map whose proportions do not match the picture's is refused.

  Anything this does not carry over is an `{:error, _}` and the caller keeps its ordinary
  SDR rendition: no `ffmpeg` (or one older than 7.1), no `tmap` item, a map with a value
  per colour channel or going from the HDR picture to the SDR one, a map of another
  shape. An HDR rendition is a bonus, never a reason for a size to be missing.
  """

  require Logger

  alias PhoenixKit.Modules.Storage.HdrResize
  alias PhoenixKit.Modules.Storage.HeifBoxes
  alias PhoenixKit.Modules.Storage.ImageProcessor

  # The gain map is detail the eye does not see, but its precision is brightness.
  @gain_map_quality 90

  # Above any real camera; the gain map's header is read before ffmpeg decodes it.
  @max_pixels 100_000_000

  # How much the gain map's proportions may differ from the picture's (rounding of
  # odd sizes), as a fraction.
  @aspect_tolerance 0.02

  @timeout_seconds 120
  @min_ffmpeg {7, 1}

  @xmp "http://ns.adobe.com/xap/1.0/\0"

  @type result ::
          {:ok, %{width: pos_integer(), height: pos_integer(), gain_map_bytes: pos_integer()}}

  @doc """
  Whether this install can decode a HEIC gain map: `ffmpeg` and `ffprobe` are there and
  `ffmpeg` is 7.1 or later (earlier versions cannot compose a tile grid). Checked once
  per node; a build with no version number (a git snapshot) is tried.
  """
  @spec available?() :: boolean()
  def available? do
    case :persistent_term.get({__MODULE__, :available}, :unknown) do
      :unknown ->
        available = detect_ffmpeg()
        :persistent_term.put({__MODULE__, :available}, available)
        available

      available ->
        available
    end
  end

  @doc false
  def reset_available, do: :persistent_term.erase({__MODULE__, :available})

  defp detect_ffmpeg do
    if System.find_executable("ffmpeg") && System.find_executable("ffprobe") do
      case System.cmd("ffmpeg", ["-version"], stderr_to_stdout: true) do
        {output, 0} -> version_ok?(output)
        _ -> false
      end
    else
      Logger.warning("HEIC HDR renditions need ffmpeg and ffprobe; making ordinary ones")
      false
    end
  rescue
    _ -> false
  end

  @doc false
  # Whether `ffmpeg -version`'s output names a release that can compose a grid.
  def version_ok?(output) do
    case Regex.run(~r/^ffmpeg version [nN]?(\d+)\.(\d+)/, output) do
      [_, major, minor] ->
        ok? = {String.to_integer(major), String.to_integer(minor)} >= @min_ffmpeg

        unless ok?,
          do:
            Logger.warning(
              "HEIC HDR renditions need ffmpeg #{elem(@min_ffmpeg, 0)}.#{elem(@min_ffmpeg, 1)} or later " <>
                "(this is #{major}.#{minor}); making ordinary ones"
            )

        ok?

      _ ->
        true
    end
  end

  @doc """
  Writes a copy of the HEIC or AVIF at `source` to `dest` as a gain-map JPEG, `width`
  pixels wide (never larger than the source), at JPEG `:quality` (default 85), with
  `:strip_metadata` as for `HdrResize.resize/4`. Width and the returned dimensions are
  as displayed.
  """
  @spec resize(Path.t(), Path.t(), pos_integer(), keyword()) :: result() | {:error, term()}
  def resize(source, dest, width, opts \\ []) do
    render(source, dest, opts, fn {src_w, src_h} ->
      out_w = min(width, src_w)
      {{src_w, src_h, 0, 0}, {out_w, max(round(src_h * out_w / src_w), 1)}}
    end)
  end

  @doc """
  Writes a `width` x `height` crop of the HEIC or AVIF at `source` to `dest`, still an
  HDR photo: the picture is cropped as `ImageProcessor.resize_and_crop_focus/6` cuts
  it (the largest window of the box's shape, centered on `:focal`, `{x, y}` as
  fractions of the photo as displayed, the middle by default), and the gain map is
  cropped to the same part of it. Takes `:quality` and `:strip_metadata` like `resize/4`.
  """
  @spec crop(Path.t(), Path.t(), {pos_integer(), pos_integer()}, keyword()) ::
          result() | {:error, term()}
  def crop(source, dest, {width, height}, opts \\ []) do
    focal = Keyword.get(opts, :focal) || {0.5, 0.5}

    render(source, dest, opts, fn shown ->
      box = ImageProcessor.cap_to_original({width, height}, shown)
      {ImageProcessor.focus_window(focal, shown, box), box}
    end)
  end

  # `plan` takes the picture's displayed size and answers the window to cut from it,
  # `{width, height, left, top}`, and the size to scale it to.
  defp render(source, dest, opts, plan) do
    quality = Keyword.get(opts, :quality, 85)
    strip? = Keyword.get(opts, :strip_metadata, false)
    dir = temp_dir()

    try do
      with true <- available?() || {:error, :ffmpeg_unavailable},
           {:ok, map} <- gain_map(source),
           {:ok, {src_w, src_h}} <- ImageProcessor.extract_dimensions(source),
           {window, {out_w, out_h}} = plan.({src_w, src_h}),
           :ok <- File.mkdir_p(dir),
           {:ok, gain_png} <- decode_gain_map(source, map, Path.join(dir, "gain.png")),
           {:ok, {gm_w, gm_h}} <- ImageProcessor.extract_dimensions(gain_png),
           :ok <- check_proportions({src_w, src_h}, {gm_w, gm_h}),
           {:ok, base} <-
             cut_base(source, Path.join(dir, "base.jpg"), window, {out_w, out_h}, quality),
           gain_window = HdrResize.scale_window(window, {src_w, src_h}, {gm_w, gm_h}),
           gain_box = {max(round(out_w * gm_w / src_w), 1), max(round(out_h * gm_h / src_h), 1)},
           {:ok, gain} <-
             cut_gain(gain_png, Path.join(dir, "gain.jpg"), gain_window, gain_box, map.params) do
        gain_file = HdrResize.assemble_gain(gain.segments, gain.core, strip?)
        parts = primary_parts(base.segments)
        primary = HdrResize.assemble_primary(parts, base.core, byte_size(gain_file), strip?)

        case File.write(dest, primary <> gain_file) do
          :ok ->
            {:ok, %{width: out_w, height: out_h, gain_map_bytes: byte_size(gain_file)}}

          {:error, reason} ->
            {:error, reason}
        end
      end
    rescue
      error -> {:error, Exception.message(error)}
    catch
      :exit, reason -> {:error, {:exit, inspect(reason)}}
    after
      File.rm_rf(dir)
    end
  end

  # ── what the file says ────────────────────────────────────────

  # `%{gain_map: item, params: ...}` for a file whose tone map this can carry over.
  defp gain_map(source) do
    case File.open(source, [:read, :binary]) do
      {:ok, io} ->
        try do
          with {:ok, heif} <- HeifBoxes.read(io),
               {:ok, %{gain_map: item, params: params}} <- HeifBoxes.gain_map(io, heif),
               :ok <- supported(params),
               :ok <- check_budget(heif, item) do
            {:ok, %{gain_map: item, params: params}}
          end
        after
          File.close(io)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp supported(%{multichannel?: true}), do: {:error, :multichannel_gain_map}
  defp supported(%{backward?: true}), do: {:error, :backward_gain_map}
  defp supported(_params), do: :ok

  # The gain map's size from its `ispe` property, before anything decodes it.
  defp check_budget(heif, item) do
    heif
    |> HeifBoxes.properties_of(item)
    |> Enum.find_value(fn
      {"ispe", <<_version_flags::32, w::32, h::32>>} -> {w, h}
      _ -> nil
    end)
    |> case do
      {w, h} when w > 0 and h > 0 and w * h <= @max_pixels -> :ok
      _ -> {:error, :bad_gain_map_size}
    end
  end

  defp check_proportions({src_w, src_h}, {gm_w, gm_h}) do
    sx = gm_w / src_w
    sy = gm_h / src_h

    if abs(sx - sy) / max(sx, sy) <= @aspect_tolerance,
      do: :ok,
      else: {:error, :gain_map_mismatch}
  end

  # ── the gain map's pixels, from ffmpeg ────────────────────────

  # The map is a stream group (a grid of tiles; its id is the item's id) or a stream
  # (a single picture; its id is the item's id). `-f mov` pins the demuxer: the file is
  # a HEIF by now, and ffmpeg is not left to guess what an upload is.
  defp decode_gain_map(source, %{gain_map: item}, png) do
    with {:ok, input} <- locate(source, item),
         {_, 0} <- ffmpeg(source, input, png),
         true <- File.regular?(png) do
      {:ok, png}
    else
      {output, status} when is_integer(status) ->
        {:error, {:ffmpeg_failed, status, String.slice(output, -300, 300)}}

      {:error, reason} ->
        {:error, reason}

      false ->
        {:error, :no_gain_map_picture}
    end
  end

  defp locate(source, item) do
    args = [
      "-v",
      "error",
      "-f",
      "mov",
      "-protocol_whitelist",
      "file",
      "-show_entries",
      "stream_group=index,id:stream=index,id",
      "-of",
      "json",
      source
    ]

    case run("ffprobe", args) do
      {output, 0} -> output |> Jason.decode() |> find_input(item)
      {output, status} -> {:error, {:ffprobe_failed, status, String.slice(output, -300, 300)}}
    end
  end

  defp find_input({:ok, %{} = probe}, item) do
    group = Enum.find(probe["stream_groups"] || [], &(item_id(&1["id"]) == item))
    stream = Enum.find(probe["streams"] || [], &(item_id(&1["id"]) == item))

    cond do
      group != nil -> {:ok, {:group, group["index"]}}
      stream != nil -> {:ok, {:stream, stream["index"]}}
      true -> {:error, :gain_map_not_found}
    end
  end

  defp find_input(_other, _item), do: {:error, :unreadable_probe}

  # ffprobe prints a HEIF item's id as hex text ("0x3e").
  defp item_id("0x" <> hex) do
    case Integer.parse(hex, 16) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp item_id(n) when is_integer(n), do: n
  defp item_id(_), do: nil

  defp ffmpeg(source, input, png) do
    selection =
      case input do
        {:group, index} -> ["-filter_complex", "[0:g:#{index}]null[o]", "-map", "[o]"]
        {:stream, index} -> ["-map", "0:#{index}"]
      end

    run(
      "ffmpeg",
      [
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-y",
        "-f",
        "mov",
        "-protocol_whitelist",
        "file",
        "-i",
        source
      ] ++
        selection ++ ["-frames:v", "1", "-update", "1", png]
    )
  end

  # `timeout` (coreutils) bounds a decoder that hangs on a hostile file; without it
  # the command runs unbounded, as the video pipeline's does.
  defp run(command, args) do
    case System.find_executable("timeout") do
      nil ->
        System.cmd(command, args, stderr_to_stdout: true)

      timeout ->
        System.cmd(timeout, ["#{@timeout_seconds}", command | args], stderr_to_stdout: true)
    end
  end

  # ── cutting ───────────────────────────────────────────────────

  # The picture, cut and scaled by ImageMagick (the HEIC decoder has turned it for
  # display already). The JPEG's marker segments and its image data apart.
  defp cut_base(source, out, window, box, quality) do
    with {:ok, _} <- ImageProcessor.crop_window(source, out, window, box, quality: quality) do
      split_jpeg(out)
    end
  end

  defp cut_gain(png, out, window, box, params) do
    with {:ok, _} <-
           ImageProcessor.crop_window(png, out, window, box,
             quality: @gain_map_quality,
             gray: true
           ),
         {:ok, %{segments: segments, core: core}} <- split_jpeg(out) do
      {:ok,
       %{
         segments: jfif(segments) ++ [segment(0xE1, @xmp <> gain_xmp(params))],
         core: core
       }}
    end
  end

  defp split_jpeg(path) do
    with {:ok, bin} <- File.read(path) do
      {segments, core_at} = HdrResize.segments(bin)
      {:ok, %{segments: segments, core: binary_part(bin, core_at, byte_size(bin) - core_at)}}
    end
  end

  # ── writing ───────────────────────────────────────────────────

  # What `HdrResize` reads from a JPEG source, made for one that has none: the
  # picture's own segments from ImageMagick (JFIF, colour profile, EXIF), the XMP
  # that names the map, and the place of the Multi-Picture directory.
  defp primary_parts(segments) do
    exif =
      Enum.filter(segments, fn
        %{marker: 0xE1, payload: <<"Exif\0\0", tiff::binary>>} ->
          HdrResize.exif_orientation(tiff) in [nil, 1]

        _ ->
          false
      end)

    icc =
      Enum.filter(segments, &match?(%{marker: 0xE2, payload: <<"ICC_PROFILE\0", _::binary>>}, &1))

    %{
      segments:
        jfif(segments) ++
          exif ++ [segment(0xE1, @xmp <> primary_xmp())] ++ icc ++ [mpf_placeholder()],
      order: "II",
      attrs: {<<0, 0, 3, 0>>, <<0, 0, 0, 0>>},
      deps: {<<0::32>>, <<0::32>>}
    }
  end

  defp jfif(segments),
    do: segments |> Enum.filter(&(&1.marker == 0xE0)) |> Enum.take(1)

  defp mpf_placeholder, do: segment(0xE2, "MPF\0")

  defp segment(marker, payload) do
    %{
      marker: marker,
      at: 0,
      payload: payload,
      raw: <<0xFF, marker, byte_size(payload) + 2::16, payload::binary>>
    }
  end

  @doc false
  # The XMP packet of the picture (the directory that names the map; its length is
  # filled in when the file is assembled) and of the map (`params`'s numbers, in
  # Ultra HDR's names).
  def primary_xmp do
    ~s(<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">) <>
      ~s(<rdf:Description xmlns:hdrgm="http://ns.adobe.com/hdr-gain-map/1.0/" ) <>
      ~s(xmlns:Container="http://ns.google.com/photos/1.0/container/" ) <>
      ~s(xmlns:Item="http://ns.google.com/photos/1.0/container/item/" hdrgm:Version="1.0">) <>
      ~s(<Container:Directory><rdf:Seq><rdf:li rdf:parseType="Resource">) <>
      ~s(<Container:Item Item:Mime="image/jpeg" Item:Semantic="Primary"/></rdf:li>) <>
      ~s(<rdf:li rdf:parseType="Resource">) <>
      ~s(<Container:Item Item:Mime="image/jpeg" Item:Length="0" Item:Semantic="GainMap"/></rdf:li>) <>
      ~s(</rdf:Seq></Container:Directory></rdf:Description></rdf:RDF></x:xmpmeta>)
  end

  @doc false
  def gain_xmp(params) do
    ~s(<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">) <>
      ~s(<rdf:Description xmlns:hdrgm="http://ns.adobe.com/hdr-gain-map/1.0/" hdrgm:Version="1.0" ) <>
      ~s(hdrgm:GainMapMin="#{num(params.gain_map_min)}" hdrgm:GainMapMax="#{num(params.gain_map_max)}" ) <>
      ~s(hdrgm:Gamma="#{num(params.gamma)}" hdrgm:OffsetSDR="#{num(params.base_offset)}" ) <>
      ~s(hdrgm:OffsetHDR="#{num(params.alternate_offset)}" ) <>
      ~s(hdrgm:HDRCapacityMin="#{num(params.base_headroom)}" ) <>
      ~s(hdrgm:HDRCapacityMax="#{num(params.alternate_headroom)}" ) <>
      ~s(hdrgm:BaseRenditionIsHDR="False"/></rdf:RDF></x:xmpmeta>)
  end

  defp num(x), do: :erlang.float_to_binary(x * 1.0, decimals: 6)

  defp temp_dir do
    Path.join(
      System.tmp_dir!(),
      "pk_heif_hdr_#{System.unique_integer([:positive])}_#{:erlang.phash2(make_ref())}"
    )
  end
end
