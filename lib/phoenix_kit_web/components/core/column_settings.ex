defmodule PhoenixKitWeb.Components.Core.ColumnSettings do
  @moduledoc """
  Generic LIVE column-configuration modal for admin tables: a "Shown"
  list (drag to reorder via the SortableGrid hook, ✕ to remove) beside
  an "Available" list (click to add), with Reset + Close. There is no
  Apply step — the consumer applies each change immediately, so the
  table updates behind the modal as the user works.

  ## Ownership model

  Pure presentation. The consumer owns the column catalog, the selected
  list, and persistence, and implements these events. LiveView callers
  need no extra wiring; LiveComponent callers pass `target` (a CSS
  selector for the component root) so clicks and the SortableGrid hook
  reach that component instead of the host LiveView:

      add_column        %{"column_id" => id}
      remove_column     %{"column_id" => id}
      reorder_columns   %{"ordered_ids" => ids}   (from SortableGrid)
      reset_columns     %{}
      hide_column_modal %{}                        (Close / backdrop / Esc)

  ## Usage

      <.column_settings_modal
        show={@show_columns}
        columns={[%{id: "sku", label: "SKU"}, %{id: "price", label: fn -> gettext("Price") end}]}
        selected={@columns}
      />

  `columns` is every configurable column; `selected` is the shown ids in
  display order. Labels may be strings or 0-arity functions (evaluated at
  render, so gettext labels stay lazy). Ids in `selected` that are not in
  `columns` are ignored, so consumers with unmanaged always-on columns
  (a Name column outside the editor) can pass their full list.

  Shown rows use the `sortable-item` class the SortableGrid hook actually
  reads (`draggable`, item-count, `ordered_ids`). A custom class is
  ignored. Drag starts only on `.pk-drag-handle` so the remove button is
  not a drag surface.
  """

  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.Icon, only: [icon: 1]
  import PhoenixKitWeb.Components.Core.Modal, only: [modal: 1]

  attr :show, :boolean, required: true
  attr :id, :string, default: "pk-column-settings-modal"

  attr :columns, :list,
    required: true,
    doc: "Every configurable column: %{id: String.t(), label: String.t() | (-> String.t())}"

  attr :selected, :list, required: true, doc: "Shown column ids, in display order."

  attr :target, :any,
    default: nil,
    doc:
      "Optional LiveComponent CSS selector (e.g. `#my-table`). Set on every `phx-click` and on `data-sortable-target` so a LiveComponent consumer receives add/remove/reorder/reset/close."

  def column_settings_modal(assigns) do
    map = Map.new(assigns.columns, &{&1.id, &1})

    assigns =
      assigns
      |> assign(:map, map)
      |> assign(:shown, Enum.filter(assigns.selected, &Map.has_key?(map, &1)))
      |> assign(:hidden, Enum.reject(assigns.columns, &(&1.id in assigns.selected)))

    ~H"""
    <.modal :if={@show} id={@id} show on_close="hide_column_modal" max_width="lg">
      <:title>{gettext("Columns")}</:title>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <p class="text-xs uppercase text-base-content/50 mb-2">{gettext("Shown")}</p>
          <ul
            id={@id <> "-selected"}
            phx-hook="SortableGrid"
            data-sortable="true"
            data-sortable-event="reorder_columns"
            data-sortable-items=".sortable-item"
            data-sortable-handle=".pk-drag-handle"
            data-sortable-target={@target}
            class="space-y-1"
          >
            <li
              :for={id <- @shown}
              data-id={id}
              class="sortable-item flex items-center gap-2 px-2 py-1 rounded bg-base-200"
            >
              <.icon
                name="hero-bars-3"
                class="w-4 h-4 pk-drag-handle cursor-grab text-base-content/40"
              />
              <span class="flex-1 text-sm">{column_label(@map[id])}</span>
              <button
                type="button"
                phx-click="remove_column"
                phx-target={@target}
                phx-value-column_id={id}
                class="btn btn-ghost btn-xs btn-square text-error cursor-pointer"
                title={gettext("Remove")}
              >
                <.icon name="hero-x-mark" class="w-4 h-4" />
              </button>
            </li>
          </ul>
        </div>
        <div>
          <p class="text-xs uppercase text-base-content/50 mb-2">{gettext("Available")}</p>
          <ul class="space-y-1">
            <li :for={c <- @hidden}>
              <button
                type="button"
                phx-click="add_column"
                phx-target={@target}
                phx-value-column_id={c.id}
                class="flex items-center gap-2 w-full text-left text-sm px-2 py-1 rounded hover:bg-base-200 cursor-pointer transition-colors"
              >
                <.icon name="hero-plus" class="w-4 h-4 text-base-content/40" />
                <span>{column_label(c)}</span>
              </button>
            </li>
          </ul>
        </div>
      </div>
      <:actions>
        <button
          type="button"
          phx-click="reset_columns"
          phx-target={@target}
          class="btn btn-ghost btn-sm"
        >
          {gettext("Reset")}
        </button>
        <button
          type="button"
          phx-click="hide_column_modal"
          phx-target={@target}
          class="btn btn-primary btn-sm"
        >
          {gettext("Close")}
        </button>
      </:actions>
    </.modal>
    """
  end

  defp column_label(%{label: label}) when is_function(label, 0), do: label.()
  defp column_label(%{label: label}), do: label
  defp column_label(_), do: ""
end
