defmodule PhoenixKit.Modules.Storage.HeifBoxes do
  @moduledoc false

  # The item structure of a HEIF / AVIF file: what its `meta` box says (`pitm`, `iinf`,
  # `iprp`, `iref`, `iloc`, `idat`), and the ISO 21496-1 gain-map parameters of its
  # `tmap` item. Nothing is decoded; the `mdat` box is never read, but for one item's
  # bytes on request.
  #
  # Every reader here answers what it could make of the file and never raises: a box
  # it does not understand leaves that part empty, so a caller sees "no map", not a crash.

  @max_meta 16_777_216
  @max_boxes 64
  @max_item_bytes 1_048_576

  @type item :: %{type: binary(), name: binary()}
  @type t :: %{
          brand: binary(),
          meta: binary(),
          primary: non_neg_integer() | nil,
          items: %{non_neg_integer() => item()},
          props: tuple(),
          assoc: %{non_neg_integer() => [non_neg_integer()]},
          refs: [{binary(), non_neg_integer(), [non_neg_integer()]}],
          locations: %{
            non_neg_integer() => %{
              method: 0..2,
              extents: [{non_neg_integer(), non_neg_integer()}]
            }
          },
          idat: binary()
        }

  @doc """
  The structure of the HEIF file open as `io`, `{:error, :not_heif}` when it has no
  `ftyp` and `meta` box.
  """
  @spec read(:file.io_device()) :: {:ok, t()} | {:error, :not_heif}
  def read(io) do
    with {:ok, brand, meta} <- top_level(io, 0, nil, nil, 0) do
      sections = children(meta)
      {props, assoc} = sections |> section("iprp") |> properties()

      {:ok,
       %{
         brand: brand,
         meta: meta,
         primary: sections |> section("pitm") |> primary_item(),
         items: sections |> section("iinf") |> items(),
         props: props,
         assoc: assoc,
         refs: sections |> section("iref") |> references(),
         locations: sections |> section("iloc") |> locations(),
         idat: section(sections, "idat") || <<>>
       }}
    end
  rescue
    _ -> {:error, :not_heif}
  end

  @doc "Whether `heif` lists an item of `type` (`tmap`, `grid`, ...)."
  @spec item_of_type?(t(), binary()) :: boolean()
  def item_of_type?(%{items: items}, type), do: Enum.any?(items, fn {_, i} -> i.type == type end)

  @doc "The ids of the items of `type`, ascending."
  @spec items_of_type(t(), binary()) :: [non_neg_integer()]
  def items_of_type(%{items: items}, type) do
    for({id, %{type: ^type}} <- items, do: id) |> Enum.sort()
  end

  @doc "The properties (`{type, payload}`) associated with `item_id`, in order."
  @spec properties_of(t(), non_neg_integer()) :: [{binary(), binary()}]
  def properties_of(%{props: props, assoc: assoc}, item_id) do
    for index <- Map.get(assoc, item_id, []),
        index >= 1 and index <= tuple_size(props),
        do: elem(props, index - 1)
  end

  @doc "The items `from` refers to by `type` (`dimg`, `auxl`, ...), in order."
  @spec references(t(), binary(), non_neg_integer()) :: [non_neg_integer()]
  def references(%{refs: refs}, type, from) do
    Enum.flat_map(refs, fn
      {^type, ^from, to} -> to
      _ -> []
    end)
  end

  @doc """
  The size in bytes of an item's picture: its own data and, for a grid, its tiles'.
  `nil` when nothing is known about it.
  """
  @spec item_size(t(), non_neg_integer()) :: non_neg_integer() | nil
  def item_size(heif, id) do
    tiles = references(heif, "dimg", id)

    sizes =
      for item <- [id | tiles], %{extents: extents} <- [Map.get(heif.locations, item)] do
        extents |> Enum.map(&elem(&1, 1)) |> Enum.sum()
      end

    case sizes do
      [] -> nil
      sizes -> Enum.sum(sizes)
    end
  end

  @doc """
  The bytes of an item (at most 1 MiB; this is for small items such as `tmap`), read
  from `idat` or from the file. `nil` when the item has no data this can read.
  """
  @spec item_bytes(:file.io_device(), t(), non_neg_integer()) :: binary() | nil
  def item_bytes(io, heif, id) do
    with %{method: method, extents: extents} <- Map.get(heif.locations, id),
         true <- extents |> Enum.map(&elem(&1, 1)) |> Enum.sum() <= @max_item_bytes do
      parts =
        Enum.map(extents, fn {offset, length} ->
          case method do
            0 -> pread(io, offset, length)
            1 -> slice(heif.idat, offset, length)
            _ -> nil
          end
        end)

      if Enum.all?(parts, &is_binary/1), do: IO.iodata_to_binary(parts), else: nil
    else
      _ -> nil
    end
  end

  defp pread(io, offset, length) do
    case :file.pread(io, offset, length) do
      {:ok, data} when byte_size(data) == length -> data
      _ -> nil
    end
  end

  defp slice(bin, offset, length) when offset >= 0 and offset + length <= byte_size(bin),
    do: binary_part(bin, offset, length)

  defp slice(_bin, _offset, _length), do: nil

  # ── the top level: ftyp and meta ──────────────────────────────

  defp top_level(_io, _at, brand, meta, _n) when brand != nil and meta != nil,
    do: {:ok, brand, meta}

  defp top_level(_io, _at, _brand, _meta, n) when n >= @max_boxes, do: {:error, :not_heif}

  defp top_level(io, at, brand, meta, n) do
    with {:ok, <<size::32, type::binary-size(4), rest::binary>>} <- :file.pread(io, at, 16),
         {:ok, header, size} <- box_size(size, rest) do
      case type do
        "ftyp" when brand == nil ->
          case pread(io, at + header, 4) do
            <<brand::binary-size(4)>> -> top_level(io, at + size, brand, meta, n + 1)
            _ -> {:error, :not_heif}
          end

        "meta" when brand != nil and size - header <= @max_meta ->
          case pread(io, at + header + 4, size - header - 4) do
            body when is_binary(body) -> top_level(io, at + size, brand, body, n + 1)
            _ -> {:error, :not_heif}
          end

        _ when brand == nil ->
          # The file has to start with its type box.
          {:error, :not_heif}

        _ ->
          top_level(io, at + size, brand, meta, n + 1)
      end
    else
      _ -> {:error, :not_heif}
    end
  end

  defp box_size(1, <<big::64, _::binary>>) when big >= 16, do: {:ok, 16, big}
  defp box_size(0, _rest), do: {:error, :to_end_of_file}
  defp box_size(size, _rest) when size >= 8, do: {:ok, 8, size}
  defp box_size(_size, _rest), do: {:error, :bad_box}

  # ── boxes in memory ───────────────────────────────────────────

  # `[{type, payload}]` for the boxes that fill `bin`; whatever follows a malformed
  # box is dropped.
  defp children(bin), do: children(bin, [])

  defp children(<<size::32, type::binary-size(4), rest::binary>>, acc) do
    {header, size} =
      case {size, rest} do
        {1, <<big::64, _::binary>>} -> {16, big}
        {0, _} -> {8, byte_size(rest) + 8}
        _ -> {8, size}
      end

    payload_size = size - header
    skip = header - 8

    case rest do
      <<_::binary-size(skip), payload::binary-size(payload_size), more::binary>>
      when payload_size >= 0 ->
        children(more, [{type, payload} | acc])

      _ ->
        Enum.reverse(acc)
    end
  end

  defp children(_bin, acc), do: Enum.reverse(acc)

  defp section(boxes, type) do
    Enum.find_value(boxes, fn
      {^type, payload} -> payload
      _ -> nil
    end)
  end

  defp uint(bin, at, size) when size == 0 and at <= byte_size(bin), do: 0

  defp uint(bin, at, size) when at + size <= byte_size(bin) do
    bits = size * 8
    <<n::unsigned-size(bits)>> = binary_part(bin, at, size)
    n
  end

  # ── pitm ──────────────────────────────────────────────────────

  defp primary_item(<<0, _flags::24, id::16, _::binary>>), do: id
  defp primary_item(<<_ver, _flags::24, id::32, _::binary>>), do: id
  defp primary_item(_), do: nil

  # ── iinf ──────────────────────────────────────────────────────

  defp items(<<version, _flags::24, rest::binary>>) do
    rest =
      if version == 0,
        do: binary_part(rest, 2, byte_size(rest) - 2),
        else: binary_part(rest, 4, byte_size(rest) - 4)

    for {"infe", <<v, _flags::24, body::binary>>} <- children(rest), v >= 2, into: %{} do
      {id, <<_protection::16, type::binary-size(4), name::binary>>} =
        if v == 2 do
          <<id::16, more::binary>> = body
          {id, more}
        else
          <<id::32, more::binary>> = body
          {id, more}
        end

      {id, %{type: type, name: name |> :binary.split(<<0>>) |> hd()}}
    end
  rescue
    _ -> %{}
  end

  defp items(_), do: %{}

  # ── iprp: ipco (the properties) and ipma (which item has which) ──

  defp properties(nil), do: {{}, %{}}

  defp properties(iprp) do
    boxes = children(iprp)
    props = boxes |> section("ipco") |> Kernel.||(<<>>) |> children() |> List.to_tuple()

    assoc =
      for {"ipma", body} <- boxes, reduce: %{} do
        acc -> Map.merge(acc, associations(body))
      end

    {props, assoc}
  rescue
    _ -> {{}, %{}}
  end

  defp associations(<<version, _::23, wide::1, count::32, rest::binary>>) do
    id_bits = if version < 1, do: 16, else: 32
    index_bits = if wide == 1, do: 16, else: 8
    {map, _} = Enum.reduce(1..count//1, {%{}, rest}, &association(&1, &2, id_bits, index_bits))
    map
  end

  defp associations(_), do: %{}

  defp association(_, {map, rest}, id_bits, index_bits) do
    <<id::size(id_bits), n, more::binary>> = rest
    {indices, more} = take_indices(more, n, index_bits, [])
    {Map.put(map, id, indices), more}
  end

  defp take_indices(rest, 0, _bits, acc), do: {Enum.reverse(acc), rest}

  defp take_indices(rest, n, bits, acc) do
    <<_essential::1, index::size(bits - 1), more::binary>> = rest
    take_indices(more, n - 1, bits, [index | acc])
  end

  # ── iref ──────────────────────────────────────────────────────

  defp references(<<version, _flags::24, rest::binary>>) do
    id_bits = if version == 0, do: 16, else: 32

    for {type, <<from::size(id_bits), count::16, targets::binary>>} <- children(rest) do
      to =
        for <<id::size(id_bits) <-
                binary_part(targets, 0, min(count * div(id_bits, 8), byte_size(targets)))>>,
            do: id

      {type, from, to}
    end
  rescue
    _ -> []
  end

  defp references(_), do: []

  # ── iloc ──────────────────────────────────────────────────────

  defp locations(<<version, _flags::24, sizes::binary-size(2), rest::binary>>)
       when version <= 2 do
    <<offset_size::4, length_size::4, base_size::4, index_size::4>> = sizes
    index_size = if version in [1, 2], do: index_size, else: 0

    {count, rest} =
      if version < 2,
        do:
          (
            <<n::16, r::binary>> = rest
            {n, r}
          ),
        else:
          (
            <<n::32, r::binary>> = rest
            {n, r}
          )

    layout = {version, offset_size, length_size, base_size, index_size}

    {map, _} =
      Enum.reduce(1..count//1, {%{}, rest}, fn _, {map, rest} ->
        {id, location, rest} = location(rest, layout)
        {Map.put(map, id, location), rest}
      end)

    map
  rescue
    _ -> %{}
  end

  defp locations(_), do: %{}

  defp location(rest, {version, offset_size, length_size, base_size, index_size}) do
    {id, rest} =
      if version < 2,
        do:
          (
            <<id::16, r::binary>> = rest
            {id, r}
          ),
        else:
          (
            <<id::32, r::binary>> = rest
            {id, r}
          )

    {method, rest} =
      if version in [1, 2],
        do:
          (
            <<_::12, m::4, r::binary>> = rest
            {m, r}
          ),
        else: {0, rest}

    <<_data_reference::16, rest::binary>> = rest
    base = uint(rest, 0, base_size)
    rest = binary_part(rest, base_size, byte_size(rest) - base_size)
    <<extent_count::16, rest::binary>> = rest

    {extents, rest} =
      Enum.reduce(1..extent_count//1, {[], rest}, fn _, {acc, rest} ->
        rest = binary_part(rest, index_size, byte_size(rest) - index_size)
        offset = uint(rest, 0, offset_size)
        length = uint(rest, offset_size, length_size)

        rest =
          binary_part(
            rest,
            offset_size + length_size,
            byte_size(rest) - offset_size - length_size
          )

        {[{base + offset, length} | acc], rest}
      end)

    {id, %{method: method, extents: Enum.reverse(extents)}, rest}
  end

  # ── the tone-map item ─────────────────────────────────────────

  @doc """
  Parses the ISO 21496-1 metadata of a `tmap` item's payload.

      {:ok, %{multichannel?: false, backward?: false, base_headroom: 0.0, alternate_headroom: 1.3298,
              gain_map_min: -0.479, gain_map_max: 1.3298, gamma: 0.9575,
              base_offset: 1.0e-5, alternate_offset: 1.0e-5}}

  Headrooms and gain-map limits are log2 quantities, as in Ultra HDR's `hdrgm`
  properties. A multichannel map keeps its first channel's values here and is flagged:
  a caller that writes one value per map cannot carry it over. `backward?` says the
  map goes from the alternate picture to the base (the base is the HDR one).
  """
  @spec tone_map(binary()) :: {:ok, map()} | {:error, term()}
  def tone_map(<<_version, 0::16, _writer::16, flags, rest::binary>>) do
    multichannel? = Bitwise.band(flags, 0x80) != 0
    backward? = Bitwise.band(flags, 0x20) != 0

    with <<bn::32, bd::32, an::32, ad::32, channel::binary-size(40), _::binary>> <- rest,
         <<mn::signed-32, mnd::32, mx::signed-32, mxd::32, gn::32, gd::32, bon::signed-32,
           bod::32, aon::signed-32, aod::32>> <- channel,
         true <- 0 not in [bd, ad, mnd, mxd, gd, bod, aod] and gn > 0 do
      {:ok,
       %{
         multichannel?: multichannel?,
         backward?: backward?,
         base_headroom: bn / bd,
         alternate_headroom: an / ad,
         gain_map_min: mn / mnd,
         gain_map_max: mx / mxd,
         gamma: gn / gd,
         base_offset: bon / bod,
         alternate_offset: aon / aod
       }}
    else
      _ -> {:error, :bad_tone_map}
    end
  end

  def tone_map(<<_version, _::binary>>), do: {:error, :unsupported_tone_map}
  def tone_map(_), do: {:error, :bad_tone_map}

  @doc """
  The tone-map parameters of the file open as `io`, with the ids of the base and the
  gain-map pictures its `tmap` item combines:

      {:ok, %{base: 46, gain_map: 62, params: %{...}}}
  """
  @spec gain_map(:file.io_device(), t()) :: {:ok, map()} | {:error, term()}
  def gain_map(io, heif) do
    with [tmap | _] <- items_of_type(heif, "tmap"),
         [base, gain | _] <- references(heif, "dimg", tmap),
         bytes when is_binary(bytes) <- item_bytes(io, heif, tmap),
         {:ok, params} <- tone_map(bytes) do
      {:ok, %{tmap: tmap, base: base, gain_map: gain, params: params}}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :no_tone_map}
    end
  end
end
