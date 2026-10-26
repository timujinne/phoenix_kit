defmodule PhoenixKit.Modules.Storage.HdrXmpTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.HdrXmp

  @xml """
  <x:xmpmeta xmlns:x="adobe:ns:meta/" x:toolkit="Camera tool">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description xmlns:gm="http://ns.adobe.com/hdr-gain-map/1.0/"
    xmlns:c="http://ns.google.com/photos/1.0/container/"
    xmlns:i="http://ns.google.com/photos/1.0/container/item/"
    xmlns:exif="http://ns.adobe.com/exif/1.0/"
    xmlns:note="http://ns.adobe.com/xmp/note/"
    rdf:about="private-photo.jpg" gm:Version="1.0" exif:GPSLatitude="59,26N">
    <exif:GPSLongitude>24,45E</exif:GPSLongitude>
    <note:HasExtendedXMP>secret-packet-id</note:HasExtendedXMP>
    <gm:GainMapMax><rdf:Seq><rdf:li>3.0</rdf:li></rdf:Seq></gm:GainMapMax>
    <c:Directory><rdf:Seq><rdf:li rdf:parseType="Resource">
    <c:Item i:Length='12345' i:Mime="image/jpeg" i:Semantic='GainMap'/>
    </rdf:li></rdf:Seq></c:Directory>
  </rdf:Description></rdf:RDF></x:xmpmeta>
  """

  test "keeps HDR parameters and updates length regardless of prefix, order and quotes" do
    result = HdrXmp.rewrite(@xml, 456, true)
    assert {:ok, _} = Saxy.SimpleForm.parse_string(result)
    assert result =~ ~s(i:Length="456")
    assert result =~ ~s(gm:Version="1.0")
    assert result =~ "<rdf:li>3.0</rdf:li>"
    refute result =~ "GPS"
    refute result =~ "59,26N"
    refute result =~ "24,45E"
    refute result =~ "private-photo"
    refute result =~ "Camera tool"
    refute result =~ "secret-packet"
  end

  test "also updates an element-valued length" do
    xml = String.replace(@xml, "i:Length='12345'", "")

    xml =
      String.replace(
        xml,
        "i:Semantic='GainMap'/>",
        "i:Semantic='GainMap'><i:Length>12345</i:Length></c:Item>"
      )

    assert HdrXmp.rewrite(xml, 456, true) =~ "<i:Length>456</i:Length>"
  end

  test "metadata is kept when requested, except the discarded extension's pointer" do
    result = HdrXmp.rewrite(@xml, 456, false)
    assert result =~ "59,26N"
    assert result =~ "24,45E"
    refute result =~ "HasExtendedXMP"
  end

  test "a packet without a new map length keeps its existing length" do
    assert HdrXmp.rewrite(@xml, nil, true) =~ ~s(i:Length="12345")
  end

  test "invalid XMP is refused instead of being copied" do
    assert_raise ArgumentError, fn -> HdrXmp.rewrite("<invalid", 456, true) end
  end

  test "Apple's gain-map headroom and auxiliary type survive stripping" do
    xml = """
    <x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description xmlns:HDRGainMap="http://ns.apple.com/HDRGainMap/1.0/"
      xmlns:apdi="http://ns.apple.com/pixeldatainfo/1.0/"
      xmlns:exif="http://ns.adobe.com/exif/1.0/" exif:GPSLatitude="59,26N">
    <HDRGainMap:HDRGainMapVersion>131072</HDRGainMap:HDRGainMapVersion>
    <HDRGainMap:HDRGainMapHeadroom>4.974161</HDRGainMap:HDRGainMapHeadroom>
    <apdi:AuxiliaryImageType>urn:com:apple:photo:2020:aux:hdrgainmap</apdi:AuxiliaryImageType>
    </rdf:Description></rdf:RDF></x:xmpmeta>
    """

    result = HdrXmp.rewrite(xml, nil, true)
    assert result =~ "<HDRGainMap:HDRGainMapHeadroom>4.974161</HDRGainMap:HDRGainMapHeadroom>"
    assert result =~ "urn:com:apple:photo:2020:aux:hdrgainmap"
    refute result =~ "GPS"
    refute result =~ "59,26N"
  end

  # An iPhone's JPEG ends its XMP packet with a NUL byte, as a C string does.
  describe "a packet written like an iPhone's" do
    @packet ~s(<?xpacket begin="\u{FEFF}" id="W5M0MpCehiHzreSzNTczkc9d"?>) <>
              ~s(<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">) <>
              ~s(<rdf:Description rdf:about=""/></rdf:RDF></x:xmpmeta>) <>
              String.duplicate(" ", 20) <> ~s(<?xpacket end="w"?>)

    test "ending in a NUL byte is read like one without" do
      assert HdrXmp.rewrite(@packet <> <<0>>, nil, false) == HdrXmp.rewrite(@packet, nil, false)
    end

    test "ending in several NUL bytes is read too" do
      assert HdrXmp.rewrite(@packet <> <<0, 0, 0>>, nil, false) ==
               HdrXmp.rewrite(@packet, nil, false)
    end

    test "that is not XML is still refused" do
      assert_raise ArgumentError, "invalid HDR XMP", fn ->
        HdrXmp.rewrite("not xml" <> <<0>>, nil, false)
      end
    end
  end
end
