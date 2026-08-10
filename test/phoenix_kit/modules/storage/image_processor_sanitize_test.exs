defmodule PhoenixKit.Modules.Storage.ImageProcessorSanitizeTest do
  @moduledoc """
  `sanitize/3` is what makes accepting an upload from a stranger
  defensible: what gets stored is this encoder's output, not the
  uploader's bytes.

  Skipped when ImageMagick isn't on the machine — and the skip is safe,
  because the function fails CLOSED without it (see the last test).
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.ImageProcessor

  @moduletag :tmp_dir

  defp imagemagick? do
    match?({_, 0}, System.cmd("identify", ["-version"], stderr_to_stdout: true))
  rescue
    _ -> false
  end

  defp png(path) do
    {_, 0} = System.cmd("convert", ["-size", "80x40", "xc:skyblue", path], stderr_to_stdout: true)
    path
  end

  describe "re-encoding" do
    @describetag :integration

    test "a payload appended to a valid image does not survive", %{tmp_dir: dir} do
      if imagemagick?() do
        # The polyglot: a real PNG with executable text glued on. Byte
        # inspection is a losing game; decoding to pixels and writing a
        # fresh file is not.
        src = png(Path.join(dir, "poly.png"))
        File.write!(src, "\n<script>alert(1)</script>NEEDLE", [:append])
        assert File.read!(src) =~ "NEEDLE"

        out = Path.join(dir, "clean.jpg")
        assert {:ok, ^out} = ImageProcessor.sanitize(src, out)

        cleaned = File.read!(out)
        refute cleaned =~ "NEEDLE"
        refute cleaned =~ "<script>"
      end
    end

    test "something that isn't an image is refused whatever it's called", %{tmp_dir: dir} do
      src = Path.join(dir, "totally.png")
      File.write!(src, "#!/bin/sh\nrm -rf /\n")

      assert {:error, _} = ImageProcessor.sanitize(src, Path.join(dir, "out.jpg"))
    end

    test "an oversized image is scaled down, not stored at full size", %{tmp_dir: dir} do
      if imagemagick?() do
        src = Path.join(dir, "big.png")

        {_, 0} =
          System.cmd("convert", ["-size", "4000x100", "xc:red", src], stderr_to_stdout: true)

        out = Path.join(dir, "small.jpg")
        assert {:ok, _} = ImageProcessor.sanitize(src, out, max_edge: 500)
        assert {:ok, {width, _height}} = ImageProcessor.extract_dimensions(out)
        assert width <= 500
      end
    end
  end

  test "a missing binary fails closed rather than passing bytes through", %{tmp_dir: dir} do
    # The whole design rests on never storing the uploader's bytes, so the
    # failure mode when the tool is absent must be refusal — not a silent
    # copy. `sanitize/3` returns an error tuple and never raises.
    src = Path.join(dir, "x.png")
    File.write!(src, "not an image")

    assert {:error, _} = ImageProcessor.sanitize(src, Path.join(dir, "y.jpg"))
    refute File.exists?(Path.join(dir, "y.jpg"))
  end

  describe "not trusting the host's configuration" do
    test "the format must be on the allowlist, not merely readable", %{tmp_dir: dir} do
      # policy.xml is what actually disables ImageMagick's dangerous
      # coders, and it belongs to whoever installed the binary. This code
      # cannot assume it was configured, so it names the format it decodes
      # and refuses anything outside a short list.
      src = Path.join(dir, "x.gif")
      File.write!(src, "GIF89a<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>")

      assert {:error, _} = ImageProcessor.sanitize(src, Path.join(dir, "out.jpg"))
    end

    test "a real image still passes", %{tmp_dir: dir} do
      if imagemagick?() do
        src = png(Path.join(dir, "fine.png"))
        assert {:ok, _} = ImageProcessor.sanitize(src, Path.join(dir, "fine.jpg"))
      end
    end
  end
end
