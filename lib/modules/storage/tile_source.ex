defmodule PhoenixKit.Modules.Storage.TileSource do
  @moduledoc """
  The image deep-zoom tiles are cut from.

  Tiles are cut by libvips (Tessera) from the file's original. libvips as shipped
  with the `vix` package can read an iPhone's HEIC for its size but has no HEVC
  decoder, so it cannot read a single pixel of it: without help a HEIC photo has no
  tiles, and the viewer stops at the largest rendition (1920 px) where a JPEG
  zooms to the last pixel. ImageMagick decodes HEIC, HEIF and AVIF.

  For those types the first request for a tile makes **one full-resolution JPEG**
  of the original with ImageMagick (`ImageProcessor.full_jpeg/3`), stores it
  beside the tiles under `_tiles/<base>_source.jpg` (a system-managed file of the
  original, so it goes with it), and every tile is cut from it. The key carries the
  original's version, so an edited original makes a new one. Any other original is
  used as it is. The caller holds the file's tile lock, so concurrent requests make
  the JPEG once.
  """

  require Logger

  alias PhoenixKit.Modules.Storage.{ImageProcessor, Manager, TesseraAdapter}

  @convert_mimes ~w(image/heic image/heif image/avif)

  @type prepared :: {:ok, Path.t(), (-> :ok)} | {:error, term()}

  @doc "Whether tiles of this original have to be cut from a converted copy."
  @spec convert?(map() | nil) :: boolean()
  def convert?(%{mime_type: mime}) when is_binary(mime),
    do: String.downcase(mime) in @convert_mimes

  def convert?(_instance), do: false

  @doc "The key, under the tiles prefix, of the converted copy of the original `base` names."
  @spec key(String.t()) :: String.t()
  def key(base), do: base <> "_source.jpg"

  @doc """
  A local path to an image the tiles can be cut from, and a function that removes
  whatever temporary files were made for it. `source` is the tile source map
  (`:base`, `:file_uuid`, `:width`, `:height`), `instance` the original's file
  instance.
  """
  @spec prepare(map(), map()) :: prepared()
  def prepare(source, instance) do
    if convert?(instance), do: converted(source, instance), else: original(instance)
  end

  defp original(instance) do
    path = temp("tessera-src")

    case Manager.retrieve_file(instance.file_name, destination_path: path) do
      {:ok, _} -> {:ok, path, remover([path])}
      {:error, _} = error -> discard(path, error)
    end
  end

  defp converted(source, instance) do
    key = key(source.base)
    destination = TesseraAdapter.destination_for(key)
    jpeg = temp("tessera-jpeg") <> ".jpg"

    if Manager.file_exists?(destination) do
      case Manager.retrieve_file(destination, destination_path: jpeg) do
        {:ok, _} -> {:ok, jpeg, remover([jpeg])}
        {:error, _} = error -> discard(jpeg, error)
      end
    else
      build(source, instance, key, jpeg)
    end
  end

  defp build(source, instance, key, jpeg) do
    original = temp("tessera-heic")

    result =
      with {:ok, _} <- Manager.retrieve_file(instance.file_name, destination_path: original),
           {:ok, _} <- ImageProcessor.full_jpeg(original, jpeg),
           :ok <- same_size(jpeg, source) do
        store(jpeg, key, source)
        {:ok, jpeg, remover([jpeg])}
      end

    File.rm(original)

    case result do
      {:ok, _, _} = ok ->
        ok

      {:error, reason} = error ->
        File.rm(jpeg)
        Logger.warning("[TileSource] no JPEG made of #{source.file_uuid}: #{inspect(reason)}")
        error
    end
  end

  # Tiles are cut by the file's recorded size; a copy of another size would put
  # every tile in the wrong place, so it is refused rather than used.
  defp same_size(jpeg, %{width: width, height: height}) do
    case ImageProcessor.extract_dimensions(jpeg) do
      {:ok, {^width, ^height}} -> :ok
      {:ok, {w, h}} -> {:error, {:dimension_mismatch, {w, h}, {width, height}}}
      {:error, _} = error -> error
    end
  end

  # Kept for the next tile. A copy that could not be kept is still used for this
  # one; the next request makes it again.
  defp store(jpeg, key, source) do
    case TesseraAdapter.put(jpeg, key,
           parent_file_uuid: source.file_uuid,
           mime_type: "image/jpeg",
           metadata: %{"kind" => "tile_source"}
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "[TileSource] could not keep the JPEG of #{source.file_uuid}: #{inspect(reason)}"
        )
    end
  end

  defp discard(path, error) do
    File.rm(path)
    error
  end

  defp remover(paths), do: fn -> Enum.each(paths, &File.rm/1) end

  defp temp(prefix),
    do: Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}")
end
