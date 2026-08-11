defmodule PhoenixKitWeb.FileController do
  @moduledoc """
  File serving controller with signed URL support.

  Handles secure file retrieval with token-based authentication and cache headers.
  """
  use PhoenixKitWeb, :controller

  require Logger

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Manager, ProcessFileJob, TesseraAdapter, URLSigner}
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Utils.Routes

  @doc """
  Serve a file variant by ID with signed URL token.

  ## Request

      GET /file/:file_uuid/:variant/:token

  ## Parameters

  - `file_uuid`: UUID of the file
  - `variant`: Variant name (e.g., "original", "thumbnail", "medium")
  - `token`: Signed token for authentication

  ## Response

  Success (200):
  - File streamed to client with appropriate headers:
    - `Cache-Control: public, max-age=31536000, immutable` (1 year)
    - `ETag: "md5-hash"`
    - `Content-Type: <mime-type>`
    - `Content-Disposition: inline; filename="..."`

  Not Modified (304):
  - Returned when request includes `If-None-Match` matching the file ETag

  Error (401):
      "Invalid or expired token"

  Error (404):
      "File or variant not found"
  """
  def show(conn, %{"file_uuid" => file_uuid, "variant" => variant, "token" => token}) do
    with {:ok, file} <- get_file(file_uuid),
         :ok <- verify_token(file_uuid, variant, token),
         {:ok, instance} <- get_file_instance(file_uuid, variant),
         result <- get_file_access(instance) do
      case result do
        {:local, file_path} ->
          serve_file(conn, file, instance, file_path)

        {:redirect, url} ->
          redirect(conn, external: url)

        {:proxy, file_name} ->
          proxy_remote_file(conn, file, instance, file_name)

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> text("File or variant not found")

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> text("Error retrieving file: #{inspect(reason)}")
      end
    else
      {:error, :invalid_token} ->
        conn
        |> put_status(:unauthorized)
        |> text("Invalid or expired token")

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> text("File or variant not found")
    end
  end

  @doc """
  Get file information without serving the file.

  ## Request

      GET /api/files/:file_uuid/info

  ## Response

  Success (200):
      {
        "file_uuid": "uuid",
        "original_filename": "photo.jpg",
        "mime_type": "image/jpeg",
        "file_type": "image",
        "size": 1234567,
        "status": "active",
        "variants": [
          {
            "variant_name": "original",
            "mime_type": "image/jpeg",
            "size": 1234567,
            "width": 1920,
            "height": 1080,
            "url": "/file/uuid/original/token"
          }
        ]
      }
  """
  def info(conn, %{"file_uuid" => file_uuid}) do
    with {:ok, user} <- require_user(conn.assigns[:phoenix_kit_current_user]),
         {:ok, file} <- authorize_file_read(Storage.get_file(file_uuid), user) do
      info_response(conn, file)
    else
      {:error, :no_user} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "UNAUTHORIZED", message: "Authentication required"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "FILE_NOT_FOUND", message: "File not found"})
    end
  end

  @doc """
  Requires an authenticated caller for the info endpoint. It lives in the
  unauthenticated `[:browser, :phoenix_kit_auto_setup]` scope, so this is the
  gate: before it, any visitor got file metadata and a freshly-minted signed URL
  for any uuid, which handed out capability URLs the signing scheme exists to
  withhold (issue #687 class).
  """
  @spec require_user(term()) :: {:ok, User.t()} | {:error, :no_user}
  def require_user(%User{} = user), do: {:ok, user}
  def require_user(_), do: {:error, :no_user}

  @doc """
  Authorizes a file-info read. The owner (`file.user_uuid`) or an Owner/Admin may
  read; everyone else — and a missing file — is `{:error, :not_found}`, the
  *same* result, so the endpoint is not a file-existence oracle.

  The staff bypass is `Scope.system_role?/1` (Owner/Admin), NOT
  `can_access_admin_area?/1`: a holder of a single module permission must not be
  able to read every other user's file metadata and signed variant URLs.
  """
  @spec authorize_file_read(term(), User.t()) :: {:ok, map()} | {:error, :not_found}
  def authorize_file_read(nil, _user), do: {:error, :not_found}

  def authorize_file_read(%{user_uuid: owner} = file, %User{uuid: uuid} = user) do
    if owner == uuid or Scope.system_role?(Scope.for_user(user)) do
      {:ok, file}
    else
      {:error, :not_found}
    end
  end

  defp info_response(conn, file) do
    file_uuid = file.uuid
    instances = Storage.list_file_instances(file_uuid)

    variant_urls =
      Enum.map(instances, fn instance ->
        token = URLSigner.generate_token(file_uuid, instance.variant_name)
        file_path = "/file/#{file_uuid}/#{instance.variant_name}/#{token}"
        url = Routes.path(file_path)

        %{
          variant_name: instance.variant_name,
          mime_type: instance.mime_type,
          size: instance.size,
          width: instance.width,
          height: instance.height,
          url: url
        }
      end)

    json(conn, %{
      file_uuid: file.uuid,
      original_filename: file.original_file_name,
      mime_type: file.mime_type,
      file_type: file.file_type,
      size: file.size,
      status: file.status,
      variants: variant_urls
    })
  end

  @doc """
  Serve the DZI manifest for an image, generating it lazily if it doesn't
  exist yet.

  ## Request

      GET /tiles/:token/:dzi_filename

  where `dzi_filename` is `"<file_uuid>.dzi"` and `token` is the signed
  per-file token from `URLSigner.generate_token(file_uuid, "dzi")`.
  Returns the XML manifest describing the image's dimensions and tile
  config — Tessera's `generate_manifest/3` produces it on first request,
  subsequent requests serve from storage.

  The token gates BOTH manifest and tile generation: without it, the
  endpoint is a 404. The MediaBrowser emits manifest URLs only when
  `storage_tile_generation_enabled` is on, so unauthenticated callers
  can't trigger lazy ImageMagick work by guessing UUIDs.
  """
  def serve_manifest(conn, %{"token" => token, "dzi_filename" => filename}) do
    with true <- tile_generation_enabled?(),
         {:ok, file_uuid} <- parse_manifest_filename(filename),
         :ok <- verify_tile_token(file_uuid, token),
         {:ok, file} <- get_file(file_uuid),
         :ok <- ensure_image(file),
         {:ok, w, h} <- ensure_dimensions(file),
         :ok <- ensure_manifest_cached(file_uuid, w, h),
         {:ok, body} <- read_tile_storage("#{file_uuid}/#{file_uuid}.dzi") do
      conn
      |> put_resp_header("cache-control", "public, max-age=300")
      |> put_resp_content_type("application/xml")
      |> send_resp(200, body)
    else
      false -> send_resp(conn, 404, "Tile generation disabled")
      :error -> send_resp(conn, 404, "Not found")
      {:error, reason} -> tile_error(conn, reason)
    end
  end

  @doc """
  Serve a single DZI tile, generating it lazily if it doesn't exist yet.

  ## Request

      GET /tiles/:token/:files_segment/:level/:tile_filename

  where `token` is the signed per-file token (same one used by
  `serve_manifest/2`), `files_segment` is `"<file_uuid>_files"`,
  `level` is the integer zoom level, and `tile_filename` is
  `"<col>_<row>.<ext>"`. This matches the layout Tessera writes to
  storage and the URL convention OpenSeadragon derives from a DZI
  manifest's base URL (token in the path survives that derivation;
  query-string tokens don't).
  """
  def serve_tile(conn, %{
        "token" => token,
        "files_segment" => files_segment,
        "level" => level,
        "tile_filename" => tile_filename
      }) do
    with true <- tile_generation_enabled?(),
         {:ok, file_uuid, level_int, col, row, ext} <-
           parse_tile_path(files_segment, level, tile_filename),
         :ok <- verify_tile_token(file_uuid, token),
         {:ok, file} <- get_file(file_uuid),
         :ok <- ensure_image(file),
         {:ok, w, h} <- ensure_dimensions(file),
         key = "#{file_uuid}/#{file_uuid}_files/#{level_int}/#{col}_#{row}.#{ext}",
         :ok <- ensure_tile_cached(file_uuid, level_int, col, row, ext, w, h, key),
         {:ok, body} <- read_tile_storage(key) do
      conn
      |> put_resp_header("cache-control", "public, max-age=31536000, immutable")
      |> put_resp_content_type(content_type_for(ext))
      |> send_resp(200, body)
    else
      false -> send_resp(conn, 404, "Tile generation disabled")
      :error -> send_resp(conn, 404, "Not found")
      {:error, reason} -> tile_error(conn, reason)
    end
  end

  # Single per-file token authorizes both the manifest and every tile
  # derived from it. Uses the same URLSigner pattern as the standard
  # `/file/:file_uuid/:variant/:token` route (`signed_url/3` →
  # `verify_token/3`); the "dzi" variant name is distinct from the
  # storage variants ("original" / "small" / "medium" / "large") so a
  # leaked file-serving token doesn't grant tile access and vice versa.
  defp verify_tile_token(file_uuid, token) do
    if URLSigner.verify_token(file_uuid, "dzi", token) do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  defp tile_generation_enabled? do
    PhoenixKit.Settings.get_setting("storage_tile_generation_enabled", "false") == "true"
  end

  # ---------------------------------------------------------------------------
  # Tile / manifest helpers
  # ---------------------------------------------------------------------------

  defp parse_manifest_filename(filename) do
    case Regex.run(~r/^([0-9a-f-]{36})\.dzi$/, filename) do
      [_, uuid] -> {:ok, uuid}
      _ -> :error
    end
  end

  defp parse_tile_path(files_segment, level, tile_filename) do
    with [_, uuid] <- Regex.run(~r/^([0-9a-f-]{36})_files$/, files_segment),
         {level_int, ""} <- Integer.parse(level),
         [_, col_str, row_str, ext] <-
           Regex.run(~r/^(\d+)_(\d+)\.(jpg|png)$/, tile_filename),
         {col, ""} <- Integer.parse(col_str),
         {row, ""} <- Integer.parse(row_str) do
      {:ok, uuid, level_int, col, row, ext}
    else
      _ -> :error
    end
  end

  defp ensure_image(%{mime_type: "image/" <> _}), do: :ok
  defp ensure_image(_), do: {:error, :not_an_image}

  defp ensure_dimensions(%{width: w, height: h}) when is_integer(w) and is_integer(h),
    do: {:ok, w, h}

  defp ensure_dimensions(_), do: {:error, :missing_dimensions}

  # Serialize concurrent first-request generators for the same manifest /
  # tile. Without `with_tile_lock`, two browser tabs racing the cold path
  # both spawn ImageMagick. The lock is keyed per source file so different
  # images stay parallel. Double-checked locking: re-test `file_exists?`
  # inside the lock so the loser of the race short-circuits to the cached
  # file the winner just wrote.

  defp ensure_manifest_cached(file_uuid, w, h) do
    destination = TesseraAdapter.destination_for("#{file_uuid}/#{file_uuid}.dzi")

    if Manager.file_exists?(destination) do
      :ok
    else
      with_tile_lock(file_uuid, fn ->
        generate_manifest_if_missing(file_uuid, w, h, destination)
      end)
    end
  end

  defp generate_manifest_if_missing(file_uuid, w, h, destination) do
    if Manager.file_exists?(destination) do
      :ok
    else
      Tessera.generate_manifest({w, h}, "#{file_uuid}/#{file_uuid}",
        storage: TesseraAdapter,
        storage_opts: [parent_file_uuid: file_uuid, mime_type: "application/xml"]
      )
    end
  end

  defp ensure_tile_cached(file_uuid, level, col, row, ext, w, h, key) do
    destination = TesseraAdapter.destination_for(key)

    if Manager.file_exists?(destination) do
      :ok
    else
      with_tile_lock(file_uuid, fn ->
        generate_tile_if_missing(file_uuid, level, col, row, ext, w, h, destination)
      end)
    end
  end

  defp generate_tile_if_missing(file_uuid, level, col, row, ext, w, h, destination) do
    if Manager.file_exists?(destination) do
      :ok
    else
      generate_tile_from_original(file_uuid, level, col, row, ext, w, h)
    end
  end

  # `:global.set_lock/3` is cluster-aware and lighter-weight than a
  # named GenServer for this access pattern (briefly-held cold-path
  # serialization). Lock retries every 50ms up to 50× = ~2.5s before
  # giving up — past that the request returns `:lock_timeout` and the
  # client retries naturally on the next viewer interaction.
  defp with_tile_lock(file_uuid, fun) do
    lock_id = {{__MODULE__, :tessera_lock, file_uuid}, self()}

    if :global.set_lock(lock_id, [node()], 50) do
      try do
        fun.()
      after
        :global.del_lock(lock_id, [node()])
      end
    else
      {:error, :lock_timeout}
    end
  end

  defp generate_tile_from_original(file_uuid, level, col, row, ext, w, h) do
    case Storage.get_file_instance_by_name(file_uuid, "original") do
      nil ->
        {:error, :original_missing}

      instance ->
        temp_path =
          Path.join(System.tmp_dir!(), "tessera-src-#{System.unique_integer([:positive])}")

        try do
          case Manager.retrieve_file(instance.file_name, destination_path: temp_path) do
            {:ok, _} ->
              Tessera.generate_tile(
                temp_path,
                {level, col, row},
                "#{file_uuid}/#{file_uuid}",
                image_width: w,
                image_height: h,
                format: format_atom(ext),
                storage: TesseraAdapter,
                storage_opts: [
                  parent_file_uuid: file_uuid,
                  mime_type: content_type_for(ext),
                  metadata: %{"level" => level, "col" => col, "row" => row}
                ]
              )

            {:error, _} = err ->
              err
          end
        after
          # Cleanup runs even if Tessera.generate_tile/4 or Manager.retrieve_file/2
          # raises mid-flight. Without this, repeated failures leak files into
          # `System.tmp_dir!()` until inode exhaustion.
          File.rm(temp_path)
        end
    end
  end

  defp read_tile_storage(key) do
    destination = TesseraAdapter.destination_for(key)
    temp_path = Path.join(System.tmp_dir!(), "tessera-read-#{System.unique_integer([:positive])}")

    try do
      case Manager.retrieve_file(destination, destination_path: temp_path) do
        {:ok, _} ->
          {:ok, File.read!(temp_path)}

        {:error, _} = err ->
          err
      end
    after
      File.rm(temp_path)
    end
  end

  defp content_type_for("jpg"), do: "image/jpeg"
  defp content_type_for("png"), do: "image/png"

  defp format_atom("jpg"), do: :jpg
  defp format_atom("png"), do: :png

  defp tile_error(conn, :not_found) do
    send_resp(conn, 404, "Not found")
  end

  # The token check fails *closed* with 404 (not 401/403) so an attacker
  # probing UUIDs can't distinguish "file exists but token is wrong"
  # from "no such file" — both look identical from outside.
  defp tile_error(conn, :unauthorized) do
    send_resp(conn, 404, "Not found")
  end

  defp tile_error(conn, :not_an_image) do
    send_resp(conn, 415, "Unsupported media type")
  end

  defp tile_error(conn, :missing_dimensions) do
    send_resp(conn, 422, "Image dimensions not available")
  end

  defp tile_error(conn, :invalid_coordinate) do
    send_resp(conn, 404, "Tile out of range")
  end

  # Source `original` instance is missing — the tile pipeline can't
  # generate anything. Surface as 404 (the user-visible state matches
  # "this tile doesn't exist") rather than 500.
  defp tile_error(conn, :original_missing) do
    send_resp(conn, 404, "Source image missing")
  end

  # Cold-path lock contention — the cluster-wide lock held by another
  # writer didn't release within ~2.5s. Tell the client to back off; the
  # next viewer interaction will retry naturally.
  defp tile_error(conn, :lock_timeout) do
    conn
    |> put_resp_header("retry-after", "2")
    |> send_resp(503, "Tile generation in progress, retry")
  end

  defp tile_error(conn, reason) do
    Logger.warning("[Tessera tile] error: #{inspect(reason)}")
    send_resp(conn, 500, "Tile generation failed")
  end

  defp get_file(file_uuid) do
    case Storage.get_file(file_uuid) do
      nil -> {:error, :not_found}
      file -> {:ok, file}
    end
  end

  defp get_file_instance(file_uuid, variant) do
    case Storage.get_file_instance_by_name(file_uuid, variant) do
      nil ->
        # Variant doesn't exist, try to get the original to queue generation
        case Storage.get_file_instance_by_name(file_uuid, "original") do
          nil ->
            {:error, :not_found}

          original_instance ->
            # Queue the variant for generation if not already requested
            queue_missing_variant(file_uuid, variant, original_instance)
            # Return the original for now
            {:ok, original_instance}
        end

      instance ->
        {:ok, instance}
    end
  end

  defp queue_missing_variant(file_uuid, _variant, original_instance) do
    # Queue background job to generate the missing variant
    Task.start(fn ->
      case Storage.get_file(file_uuid) do
        nil ->
          :error

        file ->
          %{
            file_uuid: file_uuid,
            user_uuid: file.user_uuid,
            filename: original_instance.file_name
          }
          |> ProcessFileJob.new()
          |> Oban.insert()
      end
    end)
  end

  defp verify_token(file_uuid, variant, token) do
    if URLSigner.verify_token(file_uuid, variant, token) do
      :ok
    else
      {:error, :invalid_token}
    end
  end

  # Get file access info with retry logic for bucket cache race conditions
  # Returns {:local, path} | {:redirect, url} | {:proxy, file_name} | {:error, reason}
  defp get_file_access(instance) do
    get_file_access_with_retry(instance, 5)
  end

  defp get_file_access_with_retry(instance, retries) do
    case Manager.get_file_access(instance.file_name) do
      {:local, _} = result ->
        result

      {:redirect, _} = result ->
        result

      {:proxy, _} = result ->
        result

      {:error, :not_found} when retries > 1 ->
        # Race condition during bucket cache init - retry with delay
        Logger.debug(
          "[FileController] File not found, retrying (#{retries - 1} left): #{instance.file_name}"
        )

        Process.sleep(100)
        get_file_access_with_retry(instance, retries - 1)

      error ->
        error
    end
  end

  # Serve a local file with proper headers
  defp serve_file(conn, file, instance, file_path) do
    etag = ~s("#{instance.checksum}")

    if etag in Plug.Conn.get_req_header(conn, "if-none-match") do
      conn
      |> put_resp_header("etag", etag)
      |> put_resp_header("cache-control", "public, max-age=31536000, immutable")
      |> send_resp(304, "")
    else
      conn
      |> put_resp_header("cache-control", "public, max-age=31536000, immutable")
      |> put_resp_header("etag", etag)
      |> put_resp_header(
        "content-disposition",
        ~s(inline; filename="#{file.original_file_name}")
      )
      |> put_resp_content_type(instance.mime_type)
      |> send_file(200, file_path)
    end
  end

  # Proxy a remote file through the server (for private buckets)
  defp proxy_remote_file(conn, file, instance, file_name) do
    temp_path =
      Path.join(System.tmp_dir!(), "phoenix_kit_#{instance.uuid}_#{:rand.uniform(1_000_000)}")

    case Manager.retrieve_file(file_name, destination_path: temp_path) do
      {:ok, _} ->
        conn = serve_file(conn, file, instance, temp_path)
        File.rm(temp_path)
        conn

      {:error, _reason} ->
        conn
        |> put_status(:not_found)
        |> text("File or variant not found")
    end
  end
end
