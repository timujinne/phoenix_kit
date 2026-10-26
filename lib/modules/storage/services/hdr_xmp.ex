defmodule PhoenixKit.Modules.Storage.HdrXmp do
  @moduledoc false

  # Parse XMP rather than matching its spelling: prefixes, attribute order and
  # attribute-versus-element notation do not change the meaning of a property.
  @rdf "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  @item "http://ns.google.com/photos/1.0/container/item/"
  @note "http://ns.adobe.com/xmp/note/"
  @properties %{
    "adobe:ns:meta/" => ~w(xmpmeta),
    @rdf => ~w(RDF Description Seq Bag Alt li parseType),
    "http://ns.google.com/photos/1.0/container/" => ~w(Directory Item),
    @item => ~w(Semantic Mime Length Padding),
    "http://ns.adobe.com/hdr-gain-map/1.0/" =>
      ~w(Version BaseRenditionIsHDR GainMapMin GainMapMax Gamma OffsetSDR OffsetHDR HDRCapacityMin HDRCapacityMax),
    "http://ns.apple.com/HDRGainMap/1.0/" => ~w(HDRGainMapVersion HDRGainMapHeadroom),
    "http://ns.apple.com/pixeldatainfo/1.0/" => ~w(AuxiliaryImageType)
  }

  def rewrite(xml, gain_len, strip?) do
    # Some writers (an iPhone's JPEG) end the packet with a NUL byte, as C strings
    # do. It is not part of the XMP and an XML parser refuses it.
    case Saxy.SimpleForm.parse_string(String.trim_trailing(xml, <<0>>)) do
      {:ok, tree} ->
        case rewrite_node(tree, %{}, gain_len, strip?, false) do
          nil -> raise ArgumentError, "unsupported HDR XMP"
          tree -> Saxy.encode!(tree)
        end

      {:error, _} ->
        # HdrResize returns an error and the variant generator uses its SDR path.
        # Never copy an unreadable packet when metadata removal was requested.
        raise ArgumentError, "invalid HDR XMP"
    end
  end

  defp rewrite_node({name, attrs, children}, namespaces, gain_len, strip?, gain?) do
    namespaces = Enum.reduce(attrs, namespaces, &namespace/2)
    property = property(name, namespaces)
    gain? = gain? or gain_item?(attrs, children, namespaces)

    if keep?(property, strip?) do
      attrs =
        Enum.flat_map(attrs, fn {key, value} ->
          case key do
            "xmlns" -> namespace_attr(key, value, strip?)
            "xmlns:" <> _ -> namespace_attr(key, value, strip?)
            _ -> rewrite_attr(key, value, namespaces, gain_len, strip?, gain?)
          end
        end)

      children =
        if gain? and is_integer(gain_len) and property == {@item, "Length"} do
          [to_string(gain_len)]
        else
          rewrite_children(children, namespaces, gain_len, strip?, gain?, property)
        end

      {name, attrs, children}
    end
  end

  defp rewrite_children(children, namespaces, gain_len, strip?, gain?, property) do
    Enum.flat_map(children, fn
      {_, _, _} = child ->
        case rewrite_node(child, namespaces, gain_len, strip?, gain?) do
          nil -> []
          node -> [node]
        end

      text ->
        if strip? and structural?(property), do: [], else: [text]
    end)
  end

  defp rewrite_attr(key, value, namespaces, gain_len, strip?, gain?) do
    property = property(key, namespaces)

    cond do
      gain? and is_integer(gain_len) and property == {@item, "Length"} ->
        [{key, to_string(gain_len)}]

      keep?(property, strip?) ->
        [{key, value}]

      true ->
        []
    end
  end

  defp namespace({"xmlns", uri}, acc), do: Map.put(acc, "", uri)
  defp namespace({"xmlns:" <> prefix, uri}, acc), do: Map.put(acc, prefix, uri)
  defp namespace(_, acc), do: acc

  defp namespace_attr(key, uri, strip?) do
    if not strip? or Map.has_key?(@properties, uri), do: [{key, uri}], else: []
  end

  defp property(name, namespaces) do
    case String.split(name, ":", parts: 2) do
      [prefix, local] -> {namespaces[prefix], local}
      [local] -> {namespaces[""], local}
    end
  end

  defp keep?({@note, "HasExtendedXMP"}, _strip?), do: false
  defp keep?(_property, false), do: true
  defp keep?({uri, local}, true), do: local in Map.get(@properties, uri, [])

  defp structural?({"adobe:ns:meta/", _}), do: true
  defp structural?({@rdf, local}), do: local != "li"
  defp structural?({"http://ns.google.com/photos/1.0/container/", _}), do: true
  defp structural?(_), do: false

  defp gain_item?(attrs, children, namespaces) do
    Enum.any?(attrs, fn {key, value} ->
      property(key, namespaces) == {@item, "Semantic"} and value == "GainMap"
    end) or
      Enum.any?(children, fn
        {name, attrs, ["GainMap"]} ->
          child_ns = Enum.reduce(attrs, namespaces, &namespace/2)
          property(name, child_ns) == {@item, "Semantic"}

        _ ->
          false
      end)
  end
end
