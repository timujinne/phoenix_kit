defmodule PhoenixKitWeb.Live.Users.MediaSelector do
  @moduledoc """
  Generic media selector LiveView.

  Provides a reusable interface for selecting media files from anywhere in the admin panel.
  Supports both single and multiple selection modes.

  ## Usage

      # Navigate to selector with query params
      /admin/media/selector?return_to=/admin/publishing/edit&mode=single&filter=image

  ## Query Parameters

  - `return_to` - URL to navigate back to (required)
  - `mode` - "single" or "multiple" (default: "single")
  - `selected` - Comma-separated pre-selected file IDs (optional)
  - `filter` - "image", "video", "all" (default: "all")
  - `page` - Page number for pagination (default: "1")
  """
  use PhoenixKitWeb, :live_view

  require Logger

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{File, FileInstance, URLSigner}
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.Format
  alias PhoenixKit.Utils.Routes

  import Ecto.Query

  @per_page 30

  def mount(params, _session, socket) do
    # Handle locale
    locale =
      params["locale"] || socket.assigns[:current_locale]

    # Get project title
    project_title = Settings.get_project_title()

    # Parse query parameters
    return_to = parse_return_to(params["return_to"])
    mode = parse_mode(params["mode"])
    selected_uuids = parse_selected_uuids(params["selected"])
    filter = parse_filter(params["filter"])
    page = parse_page(params["page"])

    # Allow file uploads
    socket =
      socket
      |> assign(:current_locale, locale)
      |> assign(:current_path, Routes.path("/admin/media/selector"))
      |> assign(:project_title, project_title)
      |> assign(:page_title, gettext("Select Media"))
      |> assign(:return_to, return_to)
      |> assign(:selection_mode, mode)
      |> assign(:selected_uuids, selected_uuids)
      |> assign(:file_type_filter, filter)
      |> assign(:search_query, "")
      |> assign(:current_page, page)
      |> assign(:per_page, @per_page)
      |> allow_upload(:media_files,
        accept: :any,
        max_entries: 10,
        auto_upload: true,
        progress: &handle_progress/3
      )

    {:ok, socket}
  end

  def handle_params(params, _uri, socket) do
    page = parse_page(params["page"])

    # Load files based on current filters and page
    {files, total_count} = load_files(socket, page)
    total_pages = ceil(total_count / socket.assigns.per_page)

    socket =
      socket
      |> assign(:current_page, page)
      |> assign(:uploaded_files, files)
      |> assign(:total_count, total_count)
      |> assign(:total_pages, total_pages)

    {:noreply, socket}
  end

  def handle_event("toggle_selection", %{"file-uuid" => file_uuid}, socket) do
    selected_uuids = socket.assigns.selected_uuids
    mode = socket.assigns.selection_mode

    new_selected_uuids =
      case mode do
        :single ->
          # Single mode: replace selection
          [file_uuid]

        :multiple ->
          # Multiple mode: toggle selection. Selection is an ordered list —
          # append keeps the user's pick order, which consumers receive
          # through `selected_media`.
          if file_uuid in selected_uuids do
            List.delete(selected_uuids, file_uuid)
          else
            selected_uuids ++ [file_uuid]
          end
      end

    {:noreply, assign(socket, :selected_uuids, new_selected_uuids)}
  end

  def handle_event("confirm_selection", _params, socket) do
    return_to = socket.assigns.return_to
    selected_uuids = socket.assigns.selected_uuids

    # Build return URL with selected_media param
    selected_media_param = Enum.join(selected_uuids, ",")

    return_url =
      if String.contains?(return_to, "?") do
        "#{return_to}&selected_media=#{selected_media_param}"
      else
        "#{return_to}?selected_media=#{selected_media_param}"
      end

    {:noreply, push_navigate(socket, to: return_url)}
  end

  def handle_event("cancel_selection", _params, socket) do
    {:noreply, push_navigate(socket, to: socket.assigns.return_to)}
  end

  def handle_event("search", %{"search" => %{"query" => query}}, socket) do
    socket =
      socket
      |> assign(:search_query, query)
      |> assign(:current_page, 1)

    # Reload files with search query
    {files, total_count} = load_files(socket, 1)
    total_pages = ceil(total_count / socket.assigns.per_page)

    socket =
      socket
      |> assign(:uploaded_files, files)
      |> assign(:total_count, total_count)
      |> assign(:total_pages, total_pages)

    {:noreply, socket}
  end

  def handle_event("filter_type", %{"filter" => filter}, socket) do
    parsed_filter = parse_filter(filter)

    socket =
      socket
      |> assign(:file_type_filter, parsed_filter)
      |> assign(:current_page, 1)

    # Reload files with new filter
    {files, total_count} = load_files(socket, 1)
    total_pages = ceil(total_count / socket.assigns.per_page)

    socket =
      socket
      |> assign(:uploaded_files, files)
      |> assign(:total_count, total_count)
      |> assign(:total_pages, total_pages)

    {:noreply, socket}
  end

  def handle_event("validate", _params, socket) do
    {:noreply, socket}
  end

  def handle_event("save", _params, socket) do
    # Files are auto-uploaded, just reload the list
    {files, total_count} = load_files(socket, 1)
    total_pages = ceil(total_count / socket.assigns.per_page)

    socket =
      socket
      |> assign(:current_page, 1)
      |> assign(:uploaded_files, files)
      |> assign(:total_count, total_count)
      |> assign(:total_pages, total_pages)
      |> put_flash(:info, "Files uploaded successfully")

    {:noreply, socket}
  end

  defp handle_progress(:media_files, entry, socket) do
    if entry.done? do
      result =
        consume_uploaded_entry(socket, entry, fn %{path: path} ->
          process_upload(socket, path, entry)
        end)

      socket =
        case result do
          file_uuid when is_binary(file_uuid) ->
            # Refresh the grid so the new file is visible, and auto-select it —
            # uploading into a picker means "I want this one".
            {files, total_count} = load_files(socket, 1)

            selected =
              case socket.assigns.selection_mode do
                :single -> [file_uuid]
                :multiple -> Enum.uniq(socket.assigns.selected_uuids ++ [file_uuid])
              end

            socket
            |> assign(:current_page, 1)
            |> assign(:uploaded_files, files)
            |> assign(:total_count, total_count)
            |> assign(:total_pages, ceil(total_count / socket.assigns.per_page))
            |> assign(:selected_uuids, selected)

          _ ->
            put_flash(
              socket,
              :error,
              gettext("Upload failed. Check that at least one storage bucket is configured.")
            )
        end

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  defp process_upload(socket, path, entry) do
    # Get file info
    ext = Path.extname(entry.client_name) |> String.replace_leading(".", "")
    mime_type = entry.client_type || MIME.from_path(entry.client_name)
    file_type = determine_file_type(mime_type)

    # Get current user
    current_user = socket.assigns[:phoenix_kit_current_user]
    user_uuid = if current_user, do: current_user.uuid, else: nil

    # Calculate hash
    file_hash = Auth.calculate_file_hash(path)

    # Store file in storage
    case Storage.store_file_in_buckets(
           path,
           file_type,
           user_uuid,
           file_hash,
           ext,
           entry.client_name
         ) do
      {:ok, file, :duplicate} ->
        Logger.info("Duplicate file uploaded: #{file.uuid}")
        {:ok, file.uuid}

      {:ok, file} ->
        Logger.info("New file uploaded: #{file.uuid}")
        {:ok, file.uuid}

      {:error, reason} ->
        # consume_uploaded_entry only accepts {:ok, _} | {:postpone, _} —
        # returning {:error, _} here raised and crashed the LiveView.
        Logger.error("Upload failed: #{inspect(reason)}")
        {:postpone, :error}
    end
  end

  defp load_files(socket, page) do
    repo = PhoenixKit.Config.get_repo()
    per_page = socket.assigns.per_page
    filter = socket.assigns.file_type_filter
    search = socket.assigns.search_query

    # Build query. Same exclusions as MediaSelectorModal: a picker must not
    # offer trashed or system-managed files.
    query =
      from(f in File, order_by: [desc: f.inserted_at])
      |> where([f], f.status != "trashed" and f.system_managed == false)

    # Apply file type filter
    query =
      case filter do
        :image -> where(query, [f], f.file_type == "image")
        :video -> where(query, [f], f.file_type == "video")
        :all -> query
      end

    # Apply search filter
    query =
      if search != "" do
        search_pattern = "%#{search}%"
        where(query, [f], ilike(f.original_file_name, ^search_pattern))
      else
        query
      end

    # Get total count
    total_count = repo.aggregate(query, :count, :uuid)

    # Get paginated files
    offset = (page - 1) * per_page

    files =
      query
      |> limit(^per_page)
      |> offset(^offset)
      |> repo.all()

    # Batch load instances to avoid N+1
    file_uuids = Enum.map(files, & &1.uuid)

    instances_by_file =
      if Enum.any?(file_uuids) do
        from(fi in FileInstance,
          where: fi.file_uuid in ^file_uuids
        )
        |> repo.all()
        |> Enum.group_by(& &1.file_uuid)
      else
        %{}
      end

    # Convert to file data maps
    files_with_urls =
      Enum.map(files, fn file ->
        instances = Map.get(instances_by_file, file.uuid, [])
        urls = generate_urls_from_instances(instances, file.uuid)

        %{
          file_uuid: file.uuid,
          filename: file.original_file_name || file.file_name || "Unknown",
          original_filename: file.original_file_name,
          file_type: file.file_type,
          mime_type: file.mime_type,
          size: file.size || 0,
          status: file.status,
          urls: urls,
          # Saved orientation — thumbnails apply it as a CSS transform, so
          # the picker shows images the same way up as the media grid.
          rotation: Map.get(file.metadata || %{}, "rotation"),
          width: get_width_from_instances(instances),
          height: get_height_from_instances(instances)
        }
      end)

    {files_with_urls, total_count}
  end

  defp generate_urls_from_instances(instances, file_uuid) do
    Enum.reduce(instances, %{}, fn instance, acc ->
      url = URLSigner.signed_url(file_uuid, instance.variant_name)
      Map.put(acc, instance.variant_name, url)
    end)
  end

  defp get_width_from_instances(instances) do
    case Enum.find(instances, &(&1.variant_name == "original")) do
      nil -> nil
      instance -> instance.width
    end
  end

  defp get_height_from_instances(instances) do
    case Enum.find(instances, &(&1.variant_name == "original")) do
      nil -> nil
      instance -> instance.height
    end
  end

  defp determine_file_type(mime_type) do
    cond do
      String.starts_with?(mime_type, "image/") -> "image"
      String.starts_with?(mime_type, "video/") -> "video"
      true -> "other"
    end
  end

  defp parse_mode(nil), do: :single
  defp parse_mode("single"), do: :single
  defp parse_mode("multiple"), do: :multiple
  defp parse_mode(_), do: :single

  # `return_to` is user-controlled (query param) and fed to `push_navigate` —
  # accept only local paths so a crafted link can't bounce through the selector
  # to an external site (or crash navigation with a full URL).
  defp parse_return_to(<<"/", next, _::binary>> = path) when next not in [?/, ?\\], do: path
  defp parse_return_to("/"), do: "/"
  defp parse_return_to(_), do: "/"

  # Malformed or non-positive `?page=` values fall back to 1 instead of
  # crashing the mount (String.to_integer) or producing a negative OFFSET.
  defp parse_page(page) when is_binary(page) do
    case Integer.parse(page) do
      {n, ""} when n > 0 -> n
      _ -> 1
    end
  end

  defp parse_page(_), do: 1

  defp parse_selected_uuids(nil), do: []

  defp parse_selected_uuids(selected_string) when is_binary(selected_string) do
    selected_string
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp parse_selected_uuids(_), do: []

  defp parse_filter(nil), do: :all
  defp parse_filter("image"), do: :image
  defp parse_filter("video"), do: :video
  defp parse_filter("all"), do: :all
  defp parse_filter(_), do: :all

  defp format_file_size(bytes), do: Format.bytes(bytes, decimals: 2, unknown: "0 B")

  # Folds the old in-body subtitle text + selection-count badge into a single
  # string for `page_subtitle` (string-only attr, can't carry a colored pill).
  defp selection_subtitle(:single, _count), do: gettext("Click on an image to select it")

  defp selection_subtitle(:multiple, 0), do: gettext("Select one or more images")

  defp selection_subtitle(:multiple, count) do
    gettext("Select one or more images") <>
      " — " <> ngettext("%{count} selected", "%{count} selected", count, count: count)
  end

  defp pagination_range(current_page, total_pages) do
    cond do
      total_pages <= 7 ->
        Enum.to_list(1..total_pages)

      current_page <= 4 ->
        [1, 2, 3, 4, 5, :ellipsis, total_pages]

      current_page >= total_pages - 3 ->
        [1, :ellipsis | Enum.to_list((total_pages - 4)..total_pages)]

      true ->
        [1, :ellipsis, current_page - 1, current_page, current_page + 1, :ellipsis, total_pages]
    end
  end
end
