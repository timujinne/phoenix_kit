defmodule PhoenixKit.Modules.Storage.VideoHdrPosterIntegrationTest do
  @moduledoc """
  The poster of a video, made by the real FFmpeg and the real libvips through
  `VariantGenerator.process_video_variant/4`: an HDR (HLG) video's is an HDR photo
  when its size keeps HDR, and an ordinary picture in every other case.

  Not async: some tests change the site-wide `hdr_renditions` setting.
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Modules.Storage.{Dimension, Hdr, VariantGenerator, VideoHdrPoster}

  @moduletag :tmp_dir

  unless System.find_executable("ffmpeg") && System.find_executable("ffprobe") &&
           VideoHdrPoster.available?(),
         do: @moduletag(skip: "FFmpeg, ffprobe and libvips with uhdrsave are required")

  defp clip!(dir, name, extra) do
    path = Path.join(dir, name)

    {log, status} =
      System.cmd(
        "ffmpeg",
        [
          "-hide_banner",
          "-loglevel",
          "error",
          "-f",
          "lavfi",
          "-i",
          "testsrc2=size=320x240:rate=10"
        ] ++
          ["-t", "2", "-c:v", "libx264", "-threads", "1"] ++ extra ++ ["-y", path],
        stderr_to_stdout: true
      )

    assert status == 0, log
    path
  end

  defp hlg!(dir),
    do:
      clip!(dir, "hlg.mp4", [
        "-pix_fmt",
        "yuv420p10le",
        "-x264-params",
        "colorprim=bt2020:transfer=arib-std-b67:colormatrix=bt2020nc"
      ])

  defp poster(attrs \\ []) do
    Dimension.new(
      Map.merge(
        %{
          name: "video_thumbnail",
          applies_to: "video",
          width: 160,
          height: 90,
          quality: 85,
          format: "jpg",
          maintain_aspect_ratio: true,
          keep_hdr: true
        },
        Map.new(attrs)
      )
    )
  end

  defp make!(input, dir, dimension, name \\ "poster.jpg") do
    output = Path.join(dir, name)

    assert {:ok, ^output} =
             VariantGenerator.process_video_variant(input, output, "video/mp4", dimension)

    assert File.stat!(output).size > 0
    output
  end

  defp hdr?(path), do: Hdr.gain_map?(Hdr.read(path))

  test "an HLG video's poster is an HDR photo when its size keeps HDR", ctx do
    out = make!(hlg!(ctx.tmp_dir), ctx.tmp_dir, poster())
    assert hdr?(out)

    # still a picture of the video's size, readable as a plain JPEG
    {dims, 0} = System.cmd("identify", ["-format", "%wx%h", out <> "[0]"])
    assert dims == "160x120"
  end

  test "it is an ordinary picture when the size does not keep HDR", ctx do
    out = make!(hlg!(ctx.tmp_dir), ctx.tmp_dir, poster(keep_hdr: false))
    refute hdr?(out)
  end

  test "it is an ordinary picture when the site turns HDR renditions off", ctx do
    previous = Application.get_env(:phoenix_kit, :hdr_renditions)
    Application.put_env(:phoenix_kit, :hdr_renditions, false)

    on_exit(fn ->
      if previous == nil,
        do: Application.delete_env(:phoenix_kit, :hdr_renditions),
        else: Application.put_env(:phoenix_kit, :hdr_renditions, previous)
    end)

    refute hdr?(make!(hlg!(ctx.tmp_dir), ctx.tmp_dir, poster()))
  end

  test "an ordinary (SDR) video's poster is an ordinary picture, whatever the size says", ctx do
    # Explicitly BT.709, as a phone's SDR video is: nothing about it stops the frame
    # being converted, only the video not being HLG does.
    sdr =
      clip!(ctx.tmp_dir, "sdr.mp4", [
        "-pix_fmt",
        "yuv420p",
        "-x264-params",
        "colorprim=bt709:transfer=bt709:colormatrix=bt709"
      ])

    refute hdr?(make!(sdr, ctx.tmp_dir, poster()))
  end

  test "a size that is not a JPEG is not an HDR photo", ctx do
    out = make!(hlg!(ctx.tmp_dir), ctx.tmp_dir, poster(format: "webp"), "poster.webp")
    refute hdr?(out)
  end

  test "when the HDR poster cannot be written the ordinary one is made instead", ctx do
    # libvips takes a quality of 1 to 100: this fails `uhdrsave` (the HDR path) but is
    # clamped by the ordinary JPEG's own mapping.
    out = make!(hlg!(ctx.tmp_dir), ctx.tmp_dir, poster(quality: 500))
    refute hdr?(out)
  end
end
