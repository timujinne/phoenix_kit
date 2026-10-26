defmodule PhoenixKit.TestSupport.HeifGainMap do
  @moduledoc """
  Builds a small AVIF with an ISO 21496-1 gain map for tests, in the layout Android
  writes: a base picture, a gain-map picture (both single AV1 items), and a `tmap`
  item that combines them (`dimg`) with its parameters in `idat`.

  The two pictures are encoded by `ffmpeg` (libaom, the `avif` muxer) as ordinary
  one-picture AVIFs and their items are put into a container written here. The file is
  not an iPhone's (those are HEVC grids), but it has the same boxes and the same
  `tmap`, and reaches `HeifHdr` through the stream rather than the group path.

  Deliberately written without `PhoenixKit.Modules.Storage.HeifBoxes`, so a test of it
  is not the code checking itself.
  """

  @default_params %{
    min_version: 0,
    base_headroom: 0.0,
    alternate_headroom: 2.0,
    gain_map_min: 0.0,
    gain_map_max: 2.0,
    gamma: 1.0,
    base_offset: 0.015625,
    alternate_offset: 0.015625
  }

  @doc "Whether this machine can build the fixture and read it back."
  def available? do
    tools? = System.find_executable("ffmpeg") && System.find_executable("convert")

    tools? != nil and encoders?() and decodes?()
  end

  defp encoders? do
    case System.cmd("ffmpeg", ["-hide_banner", "-encoders"], stderr_to_stdout: true) do
      {out, 0} -> String.contains?(out, "libaom-av1")
      _ -> false
    end
  rescue
    _ -> false
  end

  defp decodes? do
    case System.cmd("convert", ["-list", "format"], stderr_to_stdout: true) do
      {out, 0} -> Regex.match?(~r/^\s*AVIF\s/m, out)
      _ -> false
    end
  rescue
    _ -> false
  end

  @doc """
  Writes the file at `path`. Options: `:width`, `:height` (the base picture; the map is
  half that), `:rotation` (0..3, the `irot` angle: quarter turns anti-clockwise, for
  both pictures), `:params` (merged over the defaults; `:min_version` is the payload's minimum version), `:flags` (the ISO flags byte,
  default 0), `:gain_map_size` (override the map's size, `{w, h}`).

  Returns `%{width:, height:}` of the base as stored.
  """
  def build(path, opts \\ []) do
    width = Keyword.get(opts, :width, 320)
    height = Keyword.get(opts, :height, 240)
    {gw, gh} = Keyword.get(opts, :gain_map_size, {div(width, 2), div(height, 2)})
    rotation = Keyword.get(opts, :rotation, 0)
    flags = Keyword.get(opts, :flags, 0)
    params = Map.merge(@default_params, Map.new(Keyword.get(opts, :params, [])))
    dir = Path.dirname(path)
    n = System.unique_integer([:positive])

    base = encode!(Path.join(dir, "hgm_b_#{n}.avif"), width, height, :base)
    gain = encode!(Path.join(dir, "hgm_g_#{n}.avif"), gw, gh, :gain)

    File.write!(path, do_container(base, gain, params, flags, rotation))
    File.rm(base.path)
    File.rm(gain.path)

    %{width: width, height: height}
  end

  # A horizontal ramp, black to white: the base in colour (a tint on top so the picture
  # is not grey), the map in grey. After a quarter turn the ramp runs vertically, which
  # is how a test sees that both pictures were turned the same way.
  defp encode!(out, w, h, kind) do
    ramp =
      "gradients=size=#{w}x#{h}:rate=1:c0=black:c1=white:x0=0:y0=0:x1=#{w}:y1=0:nb_colors=2"

    {filter, pix_fmt} =
      case kind do
        :base -> {ramp <> ",format=yuv420p", "yuv420p"}
        :gain -> {ramp <> ",format=gray", "gray"}
      end

    {_, 0} =
      System.cmd(
        "ffmpeg",
        ~w(-hide_banner -loglevel error -y -f lavfi -i) ++
          [filter] ++
          ~w(-frames:v 1 -c:v libaom-av1 -cpu-used 8 -crf 20 -pix_fmt) ++
          [pix_fmt, "-f", "avif", out],
        stderr_to_stdout: true
      )

    bin = File.read!(out)
    meta = child(bin, "meta")
    props = meta |> child("iprp") |> child("ipco") |> boxes()
    {offset, length} = first_extent(meta)

    %{
      path: out,
      props: for({t, p} <- props, t in ["ispe", "pixi", "av1C", "colr"], do: {t, p}),
      data: binary_part(bin, offset, length)
    }
  end

  # ── reading the encoder's AVIF ────────────────────────────────

  defp boxes(bin), do: boxes(bin, [])

  defp boxes(<<size::32, type::binary-size(4), rest::binary>>, acc) when size >= 8 do
    payload_size = size - 8
    <<payload::binary-size(payload_size), more::binary>> = rest
    boxes(more, [{type, payload} | acc])
  end

  defp boxes(_, acc), do: Enum.reverse(acc)

  defp child(bin, type) do
    case Enum.find(boxes(bin), fn {t, _} -> t == type end) do
      {"meta", <<_version_flags::32, body::binary>>} -> body
      {_, body} -> body
    end
  end

  # The encoder's one item lives in `mdat`, found by its (version 0) `iloc` entry.
  defp first_extent(meta) do
    <<0, _flags::24, offset_size::4, length_size::4, _base_and_index::8, _count::16, _id::16,
      _data_reference::16, 1::16, rest::binary>> = child(meta, "iloc")

    <<offset::size(offset_size * 8), length::size(length_size * 8), _::binary>> = rest
    {offset, length}
  end

  # ── writing the container ─────────────────────────────────────

  @doc """
  The container alone, for two pictures given as `%{props: [{type, payload}], data: binary}`
  (`ispe`, `pixi`, `av1C`, `colr`): `data` need not decode, so a test of the boxes needs
  no encoder. `params` are the fields of `tone_map` (see the defaults), `flags` the ISO
  flags byte, `rotation` the `irot` angle.
  """
  def container(base, gain, params \\ %{}, flags \\ 0, rotation \\ 0) do
    params = Map.merge(@default_params, Map.new(params))
    do_container(base, gain, params, flags, rotation)
  end

  defp do_container(base, gain, params, flags, rotation) do
    ftyp = box("ftyp", "avif" <> <<0::32>> <> "avifmif1miaf")
    idat = tone_map(params, flags)
    # The container's size depends on its `iloc` offsets and these on its size: lay it
    # out once with placeholders of the final width, then with the real offsets.
    meta0 = meta(base, gain, idat, rotation, 0)
    mdat_at = byte_size(ftyp) + byte_size(meta0) + 8
    meta = meta(base, gain, idat, rotation, mdat_at)

    ftyp <> meta <> box("mdat", base.data <> gain.data)
  end

  defp meta(base, gain, idat, rotation, mdat_at) do
    base_props = base.props
    gain_props = gain.props
    irot = if rotation == 0, do: [], else: [{"irot", <<0::6, rotation::2>>}]

    props = base_props ++ gain_props ++ irot
    index = fn list -> for p <- list, do: 1 + Enum.find_index(props, &(&1 == p)) end
    essential = fn {t, _}, i -> if t in ["av1C", "irot"], do: 0x80 + i, else: i end

    assoc = fn item, list ->
      entries = Enum.zip_with(list, index.(list), essential)
      <<item::16, length(entries)>> <> :erlang.list_to_binary(entries)
    end

    ipma =
      box(
        "ipma",
        <<0::32, 3::32>> <>
          assoc.(1, base_props ++ irot) <> assoc.(2, gain_props ++ irot) <> assoc.(3, irot)
      )

    iprp = box("iprp", box("ipco", Enum.map_join(props, fn {t, p} -> box(t, p) end)) <> ipma)

    infe = fn id, type, hidden ->
      box("infe", <<2, 0::23, hidden::1, id::16, 0::16, type::binary, 0>>)
    end

    iinf =
      box(
        "iinf",
        <<0::32, 3::16>> <> infe.(1, "av01", 0) <> infe.(2, "av01", 1) <> infe.(3, "tmap", 0)
      )

    iref = box("iref", <<0::32>> <> box("dimg", <<3::16, 2::16, 1::16, 2::16>>))

    loc = fn id, method, offset, length ->
      <<id::16, 0::12, method::4, 0::16, 1::16, offset::32, length::32>>
    end

    iloc =
      box(
        "iloc",
        <<1, 0::24, 4::4, 4::4, 0::4, 0::4, 3::16>> <>
          loc.(1, 0, mdat_at, byte_size(base.data)) <>
          loc.(2, 0, mdat_at + byte_size(base.data), byte_size(gain.data)) <>
          loc.(3, 1, 0, byte_size(idat))
      )

    hdlr = box("hdlr", <<0::32, 0::32, "pict", 0::96, 0>>)
    pitm = box("pitm", <<0::32, 1::16>>)

    box("meta", <<0::32>> <> hdlr <> pitm <> iloc <> iinf <> iref <> iprp <> box("idat", idat))
  end

  # The ISO 21496-1 payload: version, minimum and writer versions, flags, the two
  # headrooms, and one channel's limits, gamma and offsets, each a fraction.
  defp tone_map(p, flags) do
    f = fn x -> <<round(x * 1_000_000)::signed-32, 1_000_000::32>> end
    u = fn x -> <<round(x * 1_000_000)::32, 1_000_000::32>> end

    <<0, p.min_version::16, 0::16, flags>> <>
      u.(p.base_headroom) <>
      u.(p.alternate_headroom) <>
      f.(p.gain_map_min) <>
      f.(p.gain_map_max) <> u.(p.gamma) <> f.(p.base_offset) <> f.(p.alternate_offset)
  end

  defp box(type, payload), do: <<byte_size(payload) + 8::32, type::binary, payload::binary>>
end
