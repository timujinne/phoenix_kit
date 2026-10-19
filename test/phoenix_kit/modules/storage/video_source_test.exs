defmodule PhoenixKit.Modules.Storage.VideoSourceTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.VideoSource

  defp json(transfer, duration) do
    Jason.encode!(%{
      "streams" => [%{"color_transfer" => transfer}],
      "format" => %{"duration" => duration}
    })
  end

  describe "parse/1" do
    test "HLG and PQ are HDR" do
      assert %{hdr?: true, duration: 8.0} = VideoSource.parse(json("arib-std-b67", "8.000000"))
      assert %{hdr?: true} = VideoSource.parse(json("smpte2084", "8.0"))
    end

    test "only HLG is flagged as HLG (PQ is HDR, but not HLG)" do
      assert %{hdr?: true, hlg?: true} = VideoSource.parse(json("arib-std-b67", "8.0"))
      assert %{hdr?: true, hlg?: false} = VideoSource.parse(json("smpte2084", "8.0"))
      assert %{hdr?: false, hlg?: false} = VideoSource.parse(json("bt709", "8.0"))
    end

    test "Dolby Vision profile 5 (no HLG or PQ base) is left alone; profile 8 is HDR" do
      dolby = fn profile ->
        Jason.encode!(%{
          "streams" => [
            %{
              "color_transfer" => "smpte2084",
              "side_data_list" => [
                %{"side_data_type" => "DOVI configuration record", "dv_profile" => profile}
              ]
            }
          ],
          "format" => %{"duration" => "5.0"}
        })
      end

      assert %{hdr?: false, hlg?: false} = VideoSource.parse(dolby.(5))
      assert %{hdr?: true} = VideoSource.parse(dolby.(8))
    end

    test "an ordinary video is not" do
      for transfer <- ["bt709", "unknown", "iec61966-2-1", nil] do
        assert %{hdr?: false} = VideoSource.parse(json(transfer, "8.0"))
      end
    end

    test "reads the duration, and no duration is nil" do
      assert %{duration: 1.0} = VideoSource.parse(json("bt709", "1.000000"))
      assert %{duration: nil} = VideoSource.parse(json("bt709", "N/A"))
      assert %{duration: nil} = VideoSource.parse(json("bt709", "0.000000"))
      assert %{duration: nil} = VideoSource.parse(Jason.encode!(%{"streams" => []}))
    end

    test "what is not ffprobe's JSON is unknown, not a crash" do
      for junk <- ["", "not json", "[]", "null"] do
        assert VideoSource.parse(junk) == VideoSource.unknown()
      end
    end
  end

  describe "poster_second/1" do
    test "is one second in for a clip of two seconds or more, or of unknown length" do
      assert VideoSource.poster_second(%{duration: 2.0}) == "00:00:01.000"
      assert VideoSource.poster_second(%{duration: 600.0}) == "00:00:01.000"
      assert VideoSource.poster_second(%{duration: nil}) == "00:00:01.000"
      assert VideoSource.poster_second(%{}) == "00:00:01.000"
    end

    test "is halfway for a shorter clip, so there is always a frame there" do
      assert VideoSource.poster_second(%{duration: 1.0}) == "00:00:00.500"
      assert VideoSource.poster_second(%{duration: 0.04}) == "00:00:00.020"
      assert VideoSource.poster_second(%{duration: 1.5}) == "00:00:00.750"
    end
  end

  test "probe/1 of a file it cannot read is unknown, not a crash" do
    assert VideoSource.probe("/nonexistent/clip.mov") == VideoSource.unknown()
  end
end
