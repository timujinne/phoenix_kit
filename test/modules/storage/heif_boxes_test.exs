defmodule PhoenixKit.Modules.Storage.HeifBoxesTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.Hdr
  alias PhoenixKit.Modules.Storage.HeifBoxes
  alias PhoenixKit.TestSupport.HeifGainMap

  @moduletag :tmp_dir

  # Two pictures whose bytes need not decode: the boxes are what is read.
  @base %{
    props: [{"ispe", <<0::32, 320::32, 240::32>>}, {"pixi", <<0::32, 3, 8, 8, 8>>}],
    data: "BASEBYTES"
  }
  @gain %{props: [{"ispe", <<0::32, 160::32, 120::32>>}], data: "GAINBYTES-GAINBYTES"}

  defp open!(ctx, bin) do
    path = Path.join(ctx.tmp_dir, "t.avif")
    File.write!(path, bin)
    File.open!(path, [:read, :binary])
  end

  defp read!(ctx, bin) do
    io = open!(ctx, bin)
    {:ok, heif} = HeifBoxes.read(io)
    {io, heif}
  end

  test "reads the items, references, properties and locations", ctx do
    {io, heif} = read!(ctx, HeifGainMap.container(@base, @gain, %{}, 0, 1))

    assert heif.brand == "avif"
    assert heif.primary == 1
    assert heif.items[1] == %{type: "av01", name: ""}
    assert HeifBoxes.items_of_type(heif, "tmap") == [3]
    assert HeifBoxes.item_of_type?(heif, "tmap")
    refute HeifBoxes.item_of_type?(heif, "grid")
    assert HeifBoxes.references(heif, "dimg", 3) == [1, 2]
    assert HeifBoxes.references(heif, "dimg", 1) == []

    assert [{"ispe", <<0::32, 320::32, 240::32>>}, {"pixi", _}, {"irot", <<1>>}] =
             HeifBoxes.properties_of(heif, 1)

    assert HeifBoxes.item_size(heif, 2) == byte_size(@gain.data)
    assert HeifBoxes.item_bytes(io, heif, 1) == @base.data
    assert HeifBoxes.item_bytes(io, heif, 2) == @gain.data
    # the tone map is in `idat`
    assert <<_::binary-size(5), _::binary>> = HeifBoxes.item_bytes(io, heif, 3)
    assert HeifBoxes.item_bytes(io, heif, 99) == nil
  end

  test "the tone map of the file: the pictures and the parameters", ctx do
    {io, heif} = read!(ctx, HeifGainMap.container(@base, @gain))

    assert {:ok, %{tmap: 3, base: 1, gain_map: 2, params: params}} = HeifBoxes.gain_map(io, heif)

    assert %{
             multichannel?: false,
             backward?: false,
             base_headroom: +0.0,
             alternate_headroom: 2.0,
             gain_map_min: +0.0,
             gain_map_max: 2.0,
             gamma: 1.0,
             base_offset: 0.015625,
             alternate_offset: 0.015625
           } = params
  end

  test "a file with no tmap item has no tone map", ctx do
    {io, heif} = read!(ctx, HeifGainMap.container(@base, @gain))
    heif = %{heif | items: Map.delete(heif.items, 3)}
    assert HeifBoxes.gain_map(io, heif) == {:error, :no_tone_map}
  end

  describe "tone_map/1" do
    defp payload(opts \\ []) do
      flags = Keyword.get(opts, :flags, 0)
      min_version = Keyword.get(opts, :min_version, 0)
      gamma_den = Keyword.get(opts, :gamma_den, 1000)

      <<0, min_version::16, 0::16, flags, 0::32, 1::32, 1330::32, 1000::32, -479::signed-32,
        1000::32, 1330::signed-32, 1000::32, 957::32, gamma_den::32, 10::signed-32, 1_000_000::32,
        10::signed-32, 1_000_000::32>>
    end

    test "reads one channel's numbers as the fractions they are" do
      assert {:ok, tone} = HeifBoxes.tone_map(payload())
      assert_in_delta tone.alternate_headroom, 1.33, 1.0e-9
      assert_in_delta tone.gain_map_min, -0.479, 1.0e-9
      assert_in_delta tone.gamma, 0.957, 1.0e-9
      assert_in_delta tone.base_offset, 1.0e-5, 1.0e-12
    end

    test "flags say a map is multichannel or runs backwards" do
      assert {:ok, %{multichannel?: true, backward?: false}} =
               HeifBoxes.tone_map(payload(flags: 0x80))

      assert {:ok, %{multichannel?: false, backward?: true}} =
               HeifBoxes.tone_map(payload(flags: 0x20))
    end

    test "refuses a newer minimum version, a zero denominator and a short payload" do
      assert HeifBoxes.tone_map(payload(min_version: 1)) == {:error, :unsupported_tone_map}
      assert HeifBoxes.tone_map(payload(gamma_den: 0)) == {:error, :bad_tone_map}
      assert HeifBoxes.tone_map(binary_part(payload(), 0, 20)) == {:error, :bad_tone_map}
      assert HeifBoxes.tone_map(<<>>) == {:error, :bad_tone_map}
    end
  end

  test "what is not a HEIF is not read", ctx do
    for bytes <- [<<0xFF, 0xD8, 0xFF, 0xE0, 0, 0>>, "", "hello world, this is text"] do
      io = open!(ctx, bytes)
      assert HeifBoxes.read(io) == {:error, :not_heif}
    end

    # a type box that claims more than the file holds, and a meta that is cut short
    cut = binary_part(HeifGainMap.container(@base, @gain), 0, 60)
    assert HeifBoxes.read(open!(ctx, cut)) == {:error, :not_heif}
  end

  test "an iloc of a version this does not know yields no locations, but the items stay", ctx do
    bin = HeifGainMap.container(@base, @gain)
    unknown = String.replace(bin, "iloc" <> <<1, 0::24>>, "iloc" <> <<9, 0::24>>)
    {_io, heif} = read!(ctx, unknown)
    assert heif.locations == %{}
    assert heif.items[3].type == "tmap"
  end

  describe "Hdr.read/1 of a HEIF with a tone map" do
    defp write!(ctx, name, bin) do
      path = Path.join(ctx.tmp_dir, name)
      File.write!(path, bin)
      path
    end

    test "fills the headroom, the parameters and the map's size", ctx do
      path = write!(ctx, "a.avif", HeifGainMap.container(@base, @gain))

      assert %{
               "gain_map" => true,
               "container" => "avif",
               "kinds" => ["iso21496"],
               "headroom" => headroom,
               "gain_map_bytes" => 19,
               "parameters" => parameters
             } = Hdr.read(path)

      assert_in_delta headroom, 4.0, 1.0e-9

      assert %{
               "gain_map_max" => 2.0,
               "gamma" => 1.0,
               "offset_sdr" => 0.015625,
               "hdr_capacity_max" => 2.0,
               "multichannel" => false
             } = parameters
    end

    test "a tmap item whose payload cannot be read is still a map, without numbers", ctx do
      path = write!(ctx, "b.avif", HeifGainMap.container(@base, @gain, %{min_version: 1}))

      summary = Hdr.read(path)
      assert %{"gain_map" => true, "kinds" => ["iso21496"]} = summary
      assert summary["headroom"] == nil
      refute Map.has_key?(summary, "parameters")
    end
  end
end
