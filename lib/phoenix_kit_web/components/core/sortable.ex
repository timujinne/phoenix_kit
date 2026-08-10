defmodule PhoenixKitWeb.Components.Core.Sortable do
  @moduledoc """
  Table-view DnD reorder helpers that compose with `<.table_default>`.

  Two components, both thin wrappers around HTML primitives that
  encode the conventions the `SortableGrid` JS hook expects:

    * `<.sortable_tbody>` — replaces the raw `<tbody>` that DnD-
      enabled tables previously had to spell out (with the
      `phx-hook`, `data-sortable`, `data-sortable-items`,
      `data-sortable-handle` and `data-sortable-event` attrs). When
      `enabled` is false, renders a plain `<tbody>` without any of
      the hook wiring — convenient for views where sort mode toggles
      DnD on/off (e.g. only enable drag when sorted by the manual
      position field).

    * `<.sortable_row>` — replaces `<.table_default_row>` for rows
      that participate in DnD. Adds the `sortable-item` class +
      `data-id` attr that the hook reads to identify each row. The
      consumer's own classes still pass through via `:class`.

  The hardcoded selectors (`.sortable-item` for items, `.pk-drag-handle`
  for the handle) match the conventions used by `<.drag_handle_cell>`
  and across every other DnD-enabled list in the workspace.

  ## Example

      <.table_default id="projects-list" size="sm">
        <.table_default_header>
          <.table_default_row>
            <.drag_handle_header_cell :if={@draggable?} />
            <.table_default_header_cell>Name</.table_default_header_cell>
            ...
          </.table_default_row>
        </.table_default_header>

        <.sortable_tbody
          id="projects-list-body"
          enabled={@draggable?}
          event="reorder_projects"
        >
          <.sortable_row :for={p <- @projects} item_id={p.uuid}>
            <.drag_handle_cell :if={@draggable?} />
            <.table_default_cell>{p.name}</.table_default_cell>
            ...
          </.sortable_row>
        </.sortable_tbody>
      </.table_default>

  The matching LV handler reads `%{"ordered_ids" => uuids, "moved_id" => uuid}`:

      def handle_event("reorder_projects", %{"ordered_ids" => ids} = params, socket)
          when is_list(ids) do
        ...
      end
  """
  use Phoenix.Component

  @doc """
  `<tbody>` configured for SortableGrid-driven DnD.

  When `enabled` is false, the hook attaches are omitted — the
  consumer's table renders identically but without drag behavior.
  Useful for view modes where the rendered order doesn't reflect
  the manual position field (e.g. sort-by-name views), since
  dragging in that state would write inconsistent positions.
  """
  attr :id, :string, required: true
  attr :enabled, :boolean, default: true
  attr :event, :string, required: true, doc: "LV event name pushed when the user drops a row."

  attr :rest, :global

  slot :inner_block, required: true

  def sortable_tbody(assigns) do
    ~H"""
    <tbody
      id={@id}
      phx-hook={if @enabled, do: "SortableGrid"}
      data-sortable={if @enabled, do: "true"}
      data-sortable-event={if @enabled, do: @event}
      data-sortable-items={if @enabled, do: ".sortable-item"}
      data-sortable-handle={if @enabled, do: ".pk-drag-handle"}
      {@rest}
    >
      {render_slot(@inner_block)}
    </tbody>
    """
  end

  @doc """
  `<tr>` that participates in DnD reordering.

  Wraps `<.table_default_row>` with the conventions SortableGrid
  needs: `sortable-item` class and `data-id` attr. Consumer classes
  pass through alongside.
  """
  attr :item_id, :string, required: true
  attr :class, :any, default: ""
  attr :rest, :global

  slot :inner_block, required: true

  def sortable_row(assigns) do
    ~H"""
    <PhoenixKitWeb.Components.Core.TableDefault.table_default_row
      class={["sortable-item", @class]}
      data-id={@item_id}
      {@rest}
    >
      {render_slot(@inner_block)}
    </PhoenixKitWeb.Components.Core.TableDefault.table_default_row>
    """
  end
end
