defmodule PhoenixKit.Modules.Storage.VideoOutputTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.{Dimension, VariantGenerator, VideoSource}

  @moduletag :tmp_dir

  unless System.find_executable("ffmpeg") && System.find_executable("ffprobe"),
    do: @moduletag(skip: "FFmpeg and ffprobe are not installed")

  setup %{tmp_dir: dir} do
    input = Path.join(dir, "input.mp4")

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
          "testsrc2=size=320x240:rate=10",
          "-t",
          "2",
          "-c:v",
          "libx264",
          "-threads",
          "1",
          "-y",
          input
        ],
        stderr_to_stdout: true
      )

    assert status == 0, log
    %{input: input}
  end

  defp render!(ctx, attrs) do
    dimension =
      Dimension.new(
        Map.merge(
          %{
            name: "clip",
            applies_to: "video",
            quality: 25,
            format: "mp4",
            width: 160,
            maintain_aspect_ratio: true
          },
          Map.new(attrs)
        )
      )

    output = Path.join(ctx.tmp_dir, "output.#{dimension.format || "mp4"}")
    args = VariantGenerator.ffmpeg_args(ctx.input, output, dimension)
    # Bound native threads so several ExUnit cases fit on a shared server.
    args = Enum.drop(args, -1) ++ ["-filter_threads", "1", "-threads", "1", output]

    {log, status} =
      System.cmd("ffmpeg", ["-hide_banner", "-loglevel", "error"] ++ args, stderr_to_stdout: true)

    assert status == 0, log

    {json, 0} =
      System.cmd("ffprobe", [
        "-v",
        "error",
        "-select_streams",
        "v:0",
        "-show_entries",
        "stream=codec_name,width,height",
        "-of",
        "json",
        output
      ])

    [stream] = Jason.decode!(json)["streams"]
    stream
  end

  test "a video fits its box without stretching or enlargement", ctx do
    stream = render!(ctx, maintain_aspect_ratio: false, width: 160, height: 90)
    assert {stream["width"], stream["height"]} == {120, 90}
    assert stream["codec_name"] == "h264"
  end

  test "a height-fixed video and poster follow their height", ctx do
    for format <- ["mp4", "jpg"] do
      stream = render!(ctx, fit_by: "height", width: nil, height: 120, format: format)
      assert {stream["width"], stream["height"]} == {160, 120}
    end

    stream = render!(ctx, fit_by: "height", width: nil, height: 500)
    assert {stream["width"], stream["height"]} == {320, 240}
  end

  test "a shared rendition's image-scale quality produces a valid video", ctx do
    stream = render!(ctx, applies_to: "both", quality: 85)
    assert stream["codec_name"] == "h264"
    assert {stream["width"], stream["height"]} == {160, 120}
  end

  test "preserving the original format produces a valid video", ctx do
    stream = render!(ctx, format: nil)
    assert stream["codec_name"] == "h264"
    assert {stream["width"], stream["height"]} == {160, 120}
  end

  describe "HDR and short clips, made with the real FFmpeg" do
    defp clip!(ctx, name, seconds, extra) do
      path = Path.join(ctx.tmp_dir, name)

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
            ["-t", to_string(seconds), "-c:v", "libx264", "-threads", "1"] ++
            extra ++ ["-y", path],
          stderr_to_stdout: true
        )

      assert status == 0, log
      path
    end

    defp hdr_clip!(ctx, name, seconds) do
      clip!(ctx, name, seconds, [
        "-pix_fmt",
        "yuv420p10le",
        "-x264-params",
        "colorprim=bt2020:transfer=arib-std-b67:colormatrix=bt2020nc"
      ])
    end

    defp make!(input, attrs, output_name, tmp_dir) do
      dimension =
        Dimension.new(
          Map.merge(
            %{
              name: "clip",
              applies_to: "video",
              quality: 25,
              format: "mp4",
              width: 160,
              maintain_aspect_ratio: true
            },
            Map.new(attrs)
          )
        )

      output = Path.join(tmp_dir, output_name)
      source = VideoSource.probe(input)
      args = VariantGenerator.ffmpeg_args(input, output, dimension, source)
      args = Enum.drop(args, -1) ++ ["-filter_threads", "1", "-threads", "1", output]

      {log, status} =
        System.cmd("ffmpeg", ["-hide_banner", "-loglevel", "error"] ++ args,
          stderr_to_stdout: true
        )

      {log, status, output}
    end

    defp video_stream!(path) do
      {json, 0} =
        System.cmd("ffprobe", [
          "-v",
          "error",
          "-select_streams",
          "v:0",
          "-show_entries",
          "stream=profile,pix_fmt,color_transfer,color_primaries",
          "-of",
          "json",
          path
        ])

      [stream] = Jason.decode!(json)["streams"]
      stream
    end

    test "an HDR source is probed as HDR, and one without HDR tags is not", ctx do
      assert %{hdr?: true, duration: duration} = VideoSource.probe(hdr_clip!(ctx, "hdr.mp4", 2))
      assert_in_delta duration, 2.0, 0.3
      assert %{hdr?: false} = VideoSource.probe(ctx.input)
    end

    test "an HDR video becomes an SDR rendition a browser plays", ctx do
      input = hdr_clip!(ctx, "hdr.mp4", 2)

      # What it was: 10-bit, HLG. What it would be without tone-mapping: still 10-bit.
      assert %{"pix_fmt" => "yuv420p10le", "color_transfer" => "arib-std-b67"} =
               video_stream!(input)

      {log, status, output} = make!(input, [], "sdr.mp4", ctx.tmp_dir)
      assert status == 0, log

      stream = video_stream!(output)
      assert stream["pix_fmt"] == "yuv420p"
      assert stream["profile"] == "High"
      assert stream["color_transfer"] == "bt709"
      assert stream["color_primaries"] == "bt709"
    end

    test "a 10-bit video that is not HDR is also made 8-bit", ctx do
      input = clip!(ctx, "ten.mp4", 2, ["-pix_fmt", "yuv420p10le"])
      {log, status, output} = make!(input, [], "eight.mp4", ctx.tmp_dir)
      assert status == 0, log
      assert %{"pix_fmt" => "yuv420p", "profile" => "High"} = video_stream!(output)
    end

    test "the poster of an HDR video is made", ctx do
      input = hdr_clip!(ctx, "hdr.mp4", 3)

      {log, status, output} =
        make!(input, [format: "jpg", quality: 85, width: 160], "poster.jpg", ctx.tmp_dir)

      assert status == 0, log
      assert File.stat!(output).size > 0
    end

    test "a one-second clip still has a poster (a frame at 1.000 s does not exist)", ctx do
      input = clip!(ctx, "short.mp4", 1, [])

      # The old fixed time: no frame there, so no file (FFmpeg itself says
      # success for some clips and an error for others, never a picture).
      {_log, _status, missing} = make_at_one_second!(input, ctx.tmp_dir)
      refute File.exists?(missing)

      {log, status, output} =
        make!(input, [format: "jpg", quality: 85, width: 160], "poster.jpg", ctx.tmp_dir)

      assert status == 0, log
      assert File.stat!(output).size > 0
    end

    defp make_at_one_second!(input, tmp_dir) do
      output = Path.join(tmp_dir, "old_poster.jpg")

      {log, status} =
        System.cmd(
          "ffmpeg",
          [
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            input,
            "-y",
            "-ss",
            "00:00:01.000",
            "-vframes",
            "1",
            output
          ],
          stderr_to_stdout: true
        )

      {log, status, output}
    end
  end
end
