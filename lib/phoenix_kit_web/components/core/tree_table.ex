defmodule PhoenixKitWeb.Components.Core.TreeTable do
  @moduledoc """
  File-explorer mechanics for table rows — the piece that turns any
  `<.table_default>` (or plain `<table>`) into a collapsible tree:
  depth indentation, a disclosure chevron, and a leading type icon,
  all inside the row's name cell.

  This is deliberately a *cell*, not a whole table component. An earlier
  monolithic tree-table (phoenix_kit_catalogue, retired 2026-06-28)
  couldn't compose with sortable column headers, column configuration,
  or card view — so the reusable core piece is the one thing every
  tree view shares: the name cell. The consumer owns the walk (which
  rows appear, in what order, at what depth) and the expanded-set
  state; this component just renders one row's tree affordances.

  ## Usage

  Walk your nested data into a flat list of `{node, depth}` rows in
  display order, skipping children of collapsed nodes, then:

      <.table_default id="files" ...>
        <.table_default_body>
          <.table_default_row :for={{node, depth} <- @tree_rows}>
            <.tree_name_cell
              depth={depth}
              expandable={node.children != []}
              expanded={MapSet.member?(@expanded, node.uuid)}
              toggle_event="toggle_node"
              value={node.uuid}
              icon={if node.folder?, do: "hero-folder", else: "hero-document-text"}
              icon_class={node.folder? && "w-4 h-4 text-warning shrink-0"}
            >
              {node.name}
            </.tree_name_cell>
            <%!-- ordinary cells for the remaining columns --%>
          </.table_default_row>
        </.table_default_body>
      </.table_default>

  The chevron pushes `toggle_event` with `%{"uuid" => value}`; the
  consumer flips the uuid in its expanded MapSet and rebuilds the
  walked rows. Non-expandable rows render a fixed-width spacer so
  names at the same depth stay aligned.
  """

  use Phoenix.Component

  import PhoenixKitWeb.Components.Core.Icon, only: [icon: 1]

  attr :depth, :integer, default: 0, doc: "Tree depth; 0 is a root row."

  attr :expandable, :boolean,
    default: false,
    doc: "Render the disclosure chevron (true) or an aligning spacer (false)."

  attr :expanded, :boolean, default: false

  attr :toggle_event, :string,
    default: nil,
    doc: "Event pushed by the chevron with `%{\"uuid\" => value}`."

  attr :toggle_target, :any,
    default: nil,
    doc: "Optional phx-target for the toggle (LiveComponent consumers)."

  attr :value, :string, default: nil, doc: "Sent as phx-value-uuid on toggle."

  attr :toggle_label, :string,
    default: "Toggle",
    doc: "aria-label for the chevron — pass a translated string."

  attr :icon, :string, default: nil, doc: "Optional heroicon rendered before the content."
  attr :icon_class, :any, default: nil, doc: "Classes for the leading icon (nil → default)."

  attr :indent, :string,
    default: "1.5rem",
    doc: "Indentation per depth level (any CSS length)."

  attr :class, :any, default: nil, doc: "Extra classes for the `<td>`."
  attr :rest, :global
  slot :inner_block, required: true

  def tree_name_cell(assigns) do
    assigns =
      assign(assigns, :icon_class_resolved, assigns.icon_class || "w-4 h-4 shrink-0")

    ~H"""
    <td class={@class} {@rest}>
      <div
        class="flex items-center gap-1.5 min-w-0"
        style={@depth > 0 && "padding-left: calc(#{@depth} * #{@indent})"}
      >
        <button
          :if={@expandable}
          type="button"
          phx-click={@toggle_event}
          phx-target={@toggle_target}
          phx-value-uuid={@value}
          class="btn btn-ghost btn-xs p-0 min-h-0 h-5 w-5 shrink-0"
          aria-expanded={to_string(@expanded)}
          aria-label={@toggle_label}
        >
          <.icon
            name={if @expanded, do: "hero-chevron-down-mini", else: "hero-chevron-right-mini"}
            class="w-4 h-4 text-base-content/50"
          />
        </button>
        <span :if={!@expandable} class="w-5 shrink-0"></span>
        <.icon :if={@icon} name={@icon} class={@icon_class_resolved} />
        <span class="min-w-0 truncate">
          {render_slot(@inner_block)}
        </span>
      </div>
    </td>
    """
  end
end
