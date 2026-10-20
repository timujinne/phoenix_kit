defmodule PhoenixKit.Modules.Storage.VideoHdrPoster do
  @moduledoc """
  The poster of an HDR video as an **HDR photo**: a JPEG with a gain map (Ultra HDR,
  ISO 21496-1), so an HDR screen shows the highlights above white and any other
  shows the ordinary picture.

  A photo's gain map is written by the camera and `HdrResize` only resizes it. A
  video frame has none, so it is computed here: libvips (`uhdrsave`, in the library
  `vix` ships) takes the frame as linear light, makes the SDR picture and the map
  between it and the HDR one, and writes both into one JPEG.

  ## The frame

  `from_pfm/3` reads what `ffmpeg` writes for a still frame in `gbrpf32le`: a PFM
  (Portable FloatMap), a three-line text header (`PF`, `<width> <height>`, a negative
  scale for little-endian) followed by `width * height * 3` floats, the bottom row
  first. The floats are linear light in BT.709, 1.0 being the peak that
  `VideoSource.linear_filter/0` was told (1000 nits for HLG). They are scaled so that
  SDR white (203 nits) is 1.0, as scRGB, which is what `uhdrsave` takes.

  ## When it is not possible

  Without `vix`, or with a libvips older than 8.17 (no `uhdrsave`), `available?/0` is
  false and the caller makes the ordinary SDR poster. Anything unexpected in the frame
  is an `{:error, _}`, never a raise: an HDR poster is a bonus, never a reason for a
  poster to be missing.
  """

  @compile {:no_warn_undefined, Vix.Vips.Image}
  @compile {:no_warn_undefined, Vix.Vips.Operation}

  alias PhoenixKit.Modules.Storage.VideoSource

  # A frame is `width * height * 12` bytes in memory (three 4-byte floats a pixel). A
  # poster is a few hundred pixels wide; this stops a corrupt header asking for gigabytes.
  @max_pixels 25_000_000

  @doc "Whether this install can write an HDR poster (libvips with `uhdrsave`)."
  @spec available?() :: boolean()
  def available? do
    Code.ensure_loaded?(Vix.Vips.Operation) and
      function_exported?(Vix.Vips.Operation, :uhdrsave, 3)
  end

  @doc """
  Writes the HDR poster `jpeg_path` from the float frame at `pfm_path`.

  Options: `:quality` (JPEG, default 85), `:peak_nits` (what 1.0 is in the frame,
  default `VideoSource.hlg_peak_nits/0`).
  """
  @spec from_pfm(Path.t(), Path.t(), keyword()) ::
          {:ok, %{width: pos_integer(), height: pos_integer()}} | {:error, term()}
  def from_pfm(pfm_path, jpeg_path, opts \\ []) do
    if available?() do
      quality = Keyword.get(opts, :quality, 85)
      peak = Keyword.get(opts, :peak_nits, VideoSource.hlg_peak_nits())

      with {:ok, binary} <- File.read(pfm_path),
           {:ok, frame} <- read_pfm(binary),
           :ok <- write(frame, jpeg_path, quality, peak / VideoSource.reference_white_nits()) do
        {:ok, %{width: frame.width, height: frame.height}}
      end
    else
      {:error, :uhdr_unavailable}
    end
  rescue
    error -> {:error, {:uhdr_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:uhdr_failed, inspect(reason)}}
  end

  defp write(%{width: width, height: height, pixels: pixels}, jpeg_path, quality, scale) do
    alias Vix.Vips.{Image, Operation}

    with {:ok, image} <- Image.new_from_binary(pixels, width, height, 3, :VIPS_FORMAT_FLOAT),
         # A PFM stores its rows bottom to top.
         {:ok, image} <- Operation.flip(image, :VIPS_DIRECTION_VERTICAL),
         {:ok, image} <- Operation.linear(image, [scale], [0.0]),
         {:ok, image} <- Operation.copy(image, interpretation: :VIPS_INTERPRETATION_scRGB) do
      Operation.uhdrsave(image, jpeg_path, Q: quality)
    end
  end

  @doc false
  # The frame of a little-endian RGB PFM: `{:ok, %{width:, height:, pixels:}}`, the
  # pixels as the binary of floats exactly as stored (bottom row first).
  @spec read_pfm(binary()) ::
          {:ok, %{width: pos_integer(), height: pos_integer(), pixels: binary()}}
          | {:error, term()}
  def read_pfm(binary) when is_binary(binary) do
    with [_, width, height, scale, rest] <-
           Regex.run(~r/\APF\s+(\d+)\s+(\d+)\s+(-?[0-9.eE+-]+)\s(.*)\z/s, binary),
         {width, ""} <- Integer.parse(width),
         {height, ""} <- Integer.parse(height) do
      cond do
        width < 1 or height < 1 or width * height > @max_pixels -> {:error, :bad_size}
        not String.starts_with?(scale, "-") -> {:error, :big_endian}
        byte_size(rest) != width * height * 12 -> {:error, :truncated}
        true -> {:ok, %{width: width, height: height, pixels: rest}}
      end
    else
      _ -> {:error, :not_a_pfm}
    end
  end
end
