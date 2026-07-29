defmodule PhoenixKitWeb.Components.Core.Pagination do
  @moduledoc """
  Pagination components for list views in PhoenixKit.

  Provides pagination controls and information display following daisyUI design patterns.

  Two flavours:

    * Page-numbered (`<.pagination>`, `<.pagination_controls>`,
      `<.pagination_info>`) — URL-param driven, suits standalone admin
      pages with deep-linkable state.

    * Load-more (`<.load_more>`) — click-driven LV event that grows
      the loaded set in place. Suits embeddable LVs (no URL routing),
      lists with DnD reorder (rows append, don't replace), and lists
      with client-side bulk-select (selection persists across loads
      because rows stay in the DOM).
  """

  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  @doc """
  Displays pagination controls with page numbers and navigation buttons.

  ## Attributes
  - `page` - Current page number (required)
  - `total_pages` - Total number of pages (required)
  - `build_url` - Function that takes page number and returns URL (required)
  - `class` - Additional CSS classes

  ## Examples

      <.pagination_controls
        page={@page}
        total_pages={@total_pages}
        build_url={&build_page_url(&1, assigns)}
      />
  """
  attr :page, :integer, required: true
  attr :total_pages, :integer, required: true
  attr :build_url, :any, required: true
  attr :class, :string, default: ""

  def pagination_controls(assigns) do
    ~H"""
    <div :if={@total_pages > 1} class={["join", @class]}>
      <%= if @page > 1 do %>
        <.link patch={@build_url.(@page - 1)} class="join-item btn btn-sm">
          « Prev
        </.link>
      <% end %>

      <%= for page_num <- pagination_range(@page, @total_pages) do %>
        <.link
          patch={@build_url.(page_num)}
          class={["join-item btn btn-sm", page_num == @page && "btn-active"]}
        >
          {page_num}
        </.link>
      <% end %>

      <%= if @page < @total_pages do %>
        <.link patch={@build_url.(@page + 1)} class="join-item btn btn-sm">
          Next »
        </.link>
      <% end %>
    </div>
    """
  end

  @doc """
  Displays pagination information showing result range.

  ## Attributes
  - `page` - Current page number (required)
  - `per_page` - Items per page (required)
  - `total_count` - Total number of items (required)
  - `class` - Additional CSS classes

  ## Examples

      <.pagination_info
        page={@page}
        per_page={@per_page}
        total_count={@total_count}
      />

      # Renders: "Showing 1 to 25 of 100 results"
      # Single-page result drops the redundant " of N" — e.g. with
      # total_count=4 and per_page=25: "Showing 1 to 4 results".
  """
  attr :page, :integer, required: true
  attr :per_page, :integer, required: true
  attr :total_count, :integer, required: true
  attr :class, :string, default: ""

  def pagination_info(assigns) do
    ~H"""
    <div class={["text-sm text-base-content/70", @class]}>
      <%= cond do %>
        <% @total_count == 0 -> %>
          No results
        <% @total_count > @per_page -> %>
          Showing {(@page - 1) * @per_page + 1} to {min(@page * @per_page, @total_count)} of {@total_count} results
        <% true -> %>
          Showing {(@page - 1) * @per_page + 1} to {min(@page * @per_page, @total_count)} results
      <% end %>
    </div>
    """
  end

  @doc """
  Renders complete pagination controls with automatic URL building.

  Simpler alternative to pagination_controls that handles URL building internally.
  Preserves all query parameters while changing page number.

  ## Attributes
  - `current_page` - Current active page number (required)
  - `total_pages` - Total number of pages available (required)
  - `base_path` - Base URL path without query params (required)
  - `params` - Map of query parameters to preserve (default: %{})

  ## Examples

      <.pagination
        current_page={@page}
        total_pages={@total_pages}
        base_path="/admin/emails"
        params={%{"search" => @filters.search, "status" => @filters.status}}
      />

      <%!-- Minimal usage --%>
      <.pagination
        current_page={1}
        total_pages={10}
        base_path="/admin/logs"
      />
  """
  attr :current_page, :integer, required: true
  attr :total_pages, :integer, required: true
  attr :base_path, :string, required: true
  attr :params, :map, default: %{}

  def pagination(assigns) do
    ~H"""
    <%= if @total_pages > 1 do %>
      <div class="flex justify-center p-4 border-t border-base-300">
        <div class="join">
          <%!-- Previous button --%>
          <%= if @current_page > 1 do %>
            <.link
              patch={build_page_url(@base_path, @params, @current_page - 1)}
              class="join-item btn btn-sm"
            >
              « Prev
            </.link>
          <% end %>
          <%!-- Page numbers (show current ± 2 pages) --%>
          <%= for page_num <- pagination_range(@current_page, @total_pages) do %>
            <.link
              patch={build_page_url(@base_path, @params, page_num)}
              class={[
                "join-item btn btn-sm",
                page_num == @current_page && "btn-active"
              ]}
            >
              {page_num}
            </.link>
          <% end %>
          <%!-- Next button --%>
          <%= if @current_page < @total_pages do %>
            <.link
              patch={build_page_url(@base_path, @params, @current_page + 1)}
              class="join-item btn btn-sm"
            >
              Next »
            </.link>
          <% end %>
        </div>
      </div>
    <% end %>
    """
  end

  @doc """
  Load-more footer for incrementally-loaded lists.

  Renders a centered "Showing N of M %{noun}" line and a "Load more"
  button (hidden when `loaded >= total`). Clicking the button emits
  the LV event named in `on_load_more`.

  Suited for embeddable LVs where URL-param pagination isn't an
  option, lists with DnD reorder (rows append rather than navigate
  away), and lists with client-side bulk-select (selection persists
  because the DOM grows, it doesn't get replaced).

  ## Attributes

  - `loaded` — number of rows currently rendered (required)
  - `total` — total rows matching the current filter/sort (required)
  - `on_load_more` — LV event name pushed on button click
    (default `"load_more"`)
  - `noun_plural` — used in the "Showing N of M %{noun}" line
    (default `"items"`)
  - `class` — additional classes on the outer wrapper
  - `infinite` — when `true`, the footer also auto-loads on scroll via
    the `InfiniteScroll` hook (the manual button stays as a fallback).
    Requires `id`. (default `false`)
  - `id` — DOM id, **required when `infinite`** (the JS hook needs it)
  - `cursor` — an opaque per-page marker (e.g. `"items-<offset>"`) that
    changes on each load. The `InfiniteScroll` hook re-fires only when it
    changes, so it both keeps firing while still on screen and ignores
    unrelated diffs. Only used when `infinite`. Defaults to `@loaded`
    (which already changes per page), so most callers can omit it; pass
    an explicit value only when `@loaded` is not a faithful page marker.

  ## Example

      <.load_more
        loaded={length(@projects)}
        total={@total_count}
        on_load_more="load_more"
        noun_plural={gettext("projects")}
      />

      <%!-- Auto-load on scroll + manual fallback --%>
      <.load_more
        id="items-load-more"
        loaded={length(@items)}
        total={@total}
        infinite
        cursor={"items-\#{@offset}"}
      />
  """
  attr :loaded, :integer, required: true
  attr :total, :integer, required: true
  attr :on_load_more, :string, default: "load_more"
  attr :noun_plural, :string, default: "items"
  attr :class, :string, default: ""
  attr :id, :string, default: nil
  attr :infinite, :boolean, default: false
  attr :cursor, :string, default: ""

  def load_more(assigns) do
    if assigns.infinite and is_nil(assigns.id) do
      raise ArgumentError,
            "<.load_more infinite> requires an `id` (the InfiniteScroll JS hook needs it)"
    end

    # Only the infinite variant renders data-cursor; skip the work otherwise.
    assigns =
      assign(
        assigns,
        :effective_cursor,
        if(assigns.infinite, do: resolve_cursor(assigns), else: "")
      )

    ~H"""
    <div
      :if={@total > 0}
      id={@id}
      phx-hook={if @infinite and @loaded < @total, do: "InfiniteScroll"}
      data-load-more-event={@on_load_more}
      data-cursor={@infinite && @effective_cursor}
      class={["flex flex-col items-center gap-2 p-4", @class]}
    >
      <p class="text-sm text-base-content/60">
        {gettext("Showing %{loaded} of %{total} %{noun}",
          loaded: @loaded,
          total: @total,
          noun: @noun_plural
        )}
      </p>
      <button
        :if={@loaded < @total}
        type="button"
        class="btn btn-sm"
        phx-click={@on_load_more}
        phx-disable-with={gettext("Loading…")}
      >
        {gettext("Load more")}
      </button>
    </div>
    """
  end

  # Private helper functions

  # Per-page marker the InfiniteScroll hook watches. An explicit `cursor`
  # wins; otherwise fall back to `loaded`, which already changes per page so
  # callers don't have to thread a cursor through just to drive auto-load.
  defp resolve_cursor(%{cursor: cursor}) when is_binary(cursor) and cursor != "", do: cursor
  defp resolve_cursor(%{loaded: loaded}) when is_integer(loaded), do: Integer.to_string(loaded)
  defp resolve_cursor(_), do: ""

  # Calculate visible page range (current page ± 2). Callers don't
  # necessarily clamp `current_page` themselves (e.g. a page number from a
  # stale bookmark or a crawled URL) — an unclamped huge current_page with a
  # small total_pages used to produce a DESCENDING range spanning billions
  # of integers (`a..b` picks step -1 whenever a > b), and iterating that in
  # the `:for` below allocated a component per step until the VM OOMed.
  # Clamping current_page into [1, max(total_pages, 1)] first guarantees
  # start_page <= end_page; the explicit `//1` step is a second, independent
  # guard — if start_page were ever still > end_page (e.g. total_pages is 0
  # so the clamp itself has nothing valid to land on), an explicit positive
  # step makes Elixir return an EMPTY range instead of auto-picking -1.
  defp pagination_range(current_page, total_pages) do
    total_pages = max(total_pages, 1)
    current_page = current_page |> max(1) |> min(total_pages)

    start_page = max(1, current_page - 2)
    end_page = min(total_pages, current_page + 2)
    start_page..end_page//1
  end

  # Build URL with query parameters and page number
  defp build_page_url(base_path, params, page) do
    # Add page to params and filter out nil/empty values
    query_params =
      params
      |> Map.put("page", page)
      |> Enum.filter(fn {_k, v} -> v != nil and v != "" end)
      |> Enum.into(%{})

    # Encode query parameters
    query_string = URI.encode_query(query_params)

    # Build final URL
    if query_string == "" do
      base_path
    else
      "#{base_path}?#{query_string}"
    end
  end
end
