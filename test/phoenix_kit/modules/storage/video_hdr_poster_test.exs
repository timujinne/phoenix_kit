defmodule PhoenixKit.Modules.Storage.VideoHdrPosterTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.{Hdr, VideoHdrPoster}

  @moduletag :tmp_dir

  # A PFM as ffmpeg writes it: "PF", the size, a negative scale (little-endian), then
  # `w * h * 3` floats with the BOTTOM row first.
  defp pfm(width, height, pixel_fun, scale \\ "-1.000000") do
    rows =
      for y <- (height - 1)..0//-1, x <- 0..(width - 1) do
        {r, g, b} = pixel_fun.(x, y)
        <<r::float-little-32, g::float-little-32, b::float-little-32>>
      end

    "PF\n#{width} #{height}\n#{scale}\n" <> IO.iodata_to_binary(rows)
  end

  # Brighter to the right, past SDR white (1.0 in the file is 1000 nits; SDR white is
  # 0.203) up to twice the peak.
  defp ramp(width),
    do: fn x, _y ->
      v = 2.0 * x / (width - 1)
      {v, v * 0.9, v * 0.8}
    end

  describe "read_pfm/1" do
    test "reads the size and keeps the pixels as stored" do
      data = pfm(4, 3, fn x, y -> {x * 1.0, y * 1.0, 0.5} end)
      assert {:ok, %{width: 4, height: 3, pixels: pixels}} = VideoHdrPoster.read_pfm(data)
      assert byte_size(pixels) == 4 * 3 * 12
      # the first pixel in the file is the bottom-left one (x 0, y 2)
      assert <<r::float-little-32, g::float-little-32, b::float-little-32, _::binary>> = pixels
      assert {r, g, b} == {0.0, 2.0, 0.5}
    end

    test "refuses what is not a little-endian RGB PFM of its stated size" do
      good = pfm(2, 2, fn _, _ -> {0.5, 0.5, 0.5} end)

      assert {:error, :not_a_pfm} = VideoHdrPoster.read_pfm("")

      assert {:error, :not_a_pfm} =
               VideoHdrPoster.read_pfm("P6\n2 2\n255\n" <> :binary.copy(<<0>>, 12))

      assert {:error, :not_a_pfm} = VideoHdrPoster.read_pfm("PF\nwide tall\n-1.0\n")

      assert {:error, :big_endian} =
               VideoHdrPoster.read_pfm(pfm(2, 2, fn _, _ -> {0.5, 0.5, 0.5} end, "1.0"))

      assert {:error, :truncated} =
               VideoHdrPoster.read_pfm(binary_part(good, 0, byte_size(good) - 1))

      assert {:error, :truncated} = VideoHdrPoster.read_pfm(good <> <<0>>)
      assert {:error, :bad_size} = VideoHdrPoster.read_pfm("PF\n0 5\n-1.0\n")
      assert {:error, :bad_size} = VideoHdrPoster.read_pfm("PF\n100000 100000\n-1.0\n")
    end
  end

  describe "from_pfm/3" do
    unless VideoHdrPoster.available?(),
      do: @moduletag(skip: "libvips with uhdrsave (vix) is not available")

    test "writes an HDR photo: a JPEG with a gain map, highlights above SDR white kept", ctx do
      pfm_path = Path.join(ctx.tmp_dir, "frame.pfm")
      jpeg = Path.join(ctx.tmp_dir, "poster.jpg")
      File.write!(pfm_path, pfm(96, 64, ramp(96)))

      assert {:ok, %{width: 96, height: 64}} =
               VideoHdrPoster.from_pfm(pfm_path, jpeg, quality: 85)

      assert %{"gain_map" => true, "container" => "jpeg"} = Hdr.read(jpeg)

      # Decoded back as scRGB (1.0 is SDR white), the right of the ramp is brighter than white.
      alias Vix.Vips.{Image, Operation}
      {:ok, {back, _}} = Operation.uhdrload(jpeg)
      assert {Image.width(back), Image.height(back)} == {96, 64}
      {:ok, scrgb} = Operation.uhdr2scrgb(back)
      {:ok, {max, _}} = Operation.max(scrgb)
      assert max > 2.0
    end

    test "is upright: the PFM's bottom row is the picture's bottom", ctx do
      pfm_path = Path.join(ctx.tmp_dir, "frame.pfm")
      jpeg = Path.join(ctx.tmp_dir, "poster.jpg")
      # Dark at the top (y 0), bright at the bottom.
      File.write!(
        pfm_path,
        pfm(32, 32, fn _x, y ->
          v = 0.05 + 0.5 * y / 31
          {v, v, v}
        end)
      )

      assert {:ok, _} = VideoHdrPoster.from_pfm(pfm_path, jpeg)

      alias Vix.Vips.{Image, Operation}
      {:ok, {back, _}} = Operation.uhdrload(jpeg)
      {:ok, scrgb} = Operation.uhdr2scrgb(back)

      {:ok, top} = Operation.extract_area(scrgb, 0, 0, 32, 8)
      {:ok, bottom} = Operation.extract_area(scrgb, 0, 24, 32, 8)
      {:ok, top_avg} = Operation.avg(top)
      {:ok, bottom_avg} = Operation.avg(bottom)
      assert bottom_avg > top_avg * 2
    end

    test "a file that is not a frame, or is missing, is an error and writes nothing", ctx do
      jpeg = Path.join(ctx.tmp_dir, "poster.jpg")
      junk = Path.join(ctx.tmp_dir, "junk.pfm")
      File.write!(junk, "not a frame")

      assert {:error, :not_a_pfm} = VideoHdrPoster.from_pfm(junk, jpeg)
      assert {:error, :enoent} = VideoHdrPoster.from_pfm(Path.join(ctx.tmp_dir, "none.pfm"), jpeg)
      refute File.exists?(jpeg)
    end
  end
end
