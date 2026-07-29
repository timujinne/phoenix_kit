defmodule PhoenixKitWeb.Components.Core.RowLink do
  @moduledoc """
  Stretched link that makes a whole table row (or card) clickable with a
  single real `<a>` element.

  Render it once at the START of the row's first cell. The row (or card)
  must be a positioned ancestor (`relative`); the link paints an
  `::after` overlay across it. Interactive siblings — row menus, buttons,
  other links — need `relative z-10` to stay clickable above the overlay.
  The link's accessible name comes from `label` (visually hidden).

  ## Table rows need `transform-gpu` (Safari)

  Safari/WebKit ignores `position: relative` on `<tr>`, so on a `<tr>` host the
  overlay escapes to the `<table>` and every row's overlay collapses onto the
  last row — on iOS/iPadOS every row then navigates to the LAST one. Give any
  `<tr>` host Tailwind's `transform-gpu` (`translateZ(0)`), which WebKit *does*
  honor as a containing block. Card/`<div>` hosts don't need it.

  `transform-gpu` is a stock Tailwind utility, so nothing has to be added to the
  host application's stylesheet. Do **not** depend on a custom class such as
  `row-link-host` for this: that rule lives in one host app's `app.css` and is
  absent from every other consumer, where the failure is invisible in source and
  only shows up on an iOS device.

  ## Import

  Not wired into `PhoenixKitWeb, :live_view` — a host app that defines its own
  `row_link/1` would get an ambiguous import. Each LiveView imports it directly:

      import PhoenixKitWeb.Components.Core.RowLink, only: [row_link: 1]

  ## Example

      <.table_default_row class="relative transform-gpu cursor-pointer">
        <.table_default_cell>
          <.row_link navigate={Routes.path("/admin/orders/123")} label="Open order #123" />
          #123
        </.table_default_cell>
        <.table_default_cell class="relative z-10"><.table_row_menu .../></.table_default_cell>
      </.table_default_row>
  """
  use Phoenix.Component

  attr :navigate, :string, required: true
  attr :label, :string, required: true, doc: "accessible name for the link (rendered sr-only)"

  def row_link(assigns) do
    ~H"""
    <.link navigate={@navigate} class="after:absolute after:inset-0 after:z-0">
      <span class="sr-only">{@label}</span>
    </.link>
    """
  end
end
