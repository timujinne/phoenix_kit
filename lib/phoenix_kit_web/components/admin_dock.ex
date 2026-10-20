defmodule PhoenixKitWeb.Components.AdminDock do
  @moduledoc """
  The optional right-hand dock column of the admin layout, and the commands that open it.

  A module's header widget (`c:PhoenixKit.Module.header_widgets/0`) that needs room beside
  the page, a chat panel for instance, declares `dock: true`. While at least one rendered
  widget does, `#admin-drawer` gets one more grid column, `#pk-dock`. Without such a widget
  the layout has no dock markup at all.

  ## Contract

    * **Container**: `#pk-dock` (`container_id/0`), the last child of `#admin-drawer`. It is
      an empty `<aside>` that is `display: none` until opened. What goes into it is the
      widget's business: the widget can position its own panel over the column (the column
      holds the width free, the panel sits at `right-0` with `w-[var(--pk-dock-width,25rem)]`),
      or move its panel element into the container with a hook.
    * **State**: the class `pk-dock-open` (`open_class/0`) on `<body>` (`target/0`) or on
      **any element inside it**, the widget's own markup included; either opens the dock.
      The page is laid out as `<body> > header` (where the widgets live) next to
      `<body> > ... > #admin-drawer > #pk-dock`, so `<body>` is the one element above both
      and the CSS looks there. Which form to use depends on how long the state has to live:
        * The JS commands below put the class on `<body>`. LiveView never patches `<body>`, so
          the class survives `push_patch`, a live redirect to another LiveView (the usual
          admin navigation, e.g. a sidebar link), and the sticky widget is not mounted again.
          A full page load resets it.
        * A class on an element of the widget itself (in the header) travels with the sticky
          widget as well. A widget that keeps "open" in its own assigns renders
          `class={[@open? && "pk-dock-open"]}` on an element of its own, and the dock is shown
          for as long as that element has the class. It needs no JavaScript and no replay on
          mount.
    * **Width**: the CSS variable `--pk-dock-width` (`width_var/0`), `25rem` when unset. The
      dock reads it inside `#admin-drawer`, a widget panel in the header reads it from the
      header: set it on `:root` or `<body>` (above both), from CSS or a style attribute, and
      write `var(--pk-dock-width,25rem)` wherever you read it.
    * **Layout**: from `lg` up the dock is a third column of the drawer grid, so the work
      area gets narrower by the dock's width; the dock is as tall as the viewport below the
      header and scrolls itself. Below `lg` it covers the whole screen under the header.

  ## Commands

      <button phx-click={AdminDock.toggle()}>Chat</button>
      <button phx-click={AdminDock.close() |> JS.push("forget_panel")}>Close</button>

  The commands target `<body>` by selector, so they work from the widget's nested LiveView,
  which sits in the header. A widget that also keeps its own class on an element of its own
  must not mix the two: when it closes, it removes the class from its element and runs
  `close/1`.

  ## Not covered by tests

  `Phoenix.LiveViewTest` has no notion of sticky LiveViews moving to the new page on a live
  redirect, so the ExUnit tests pin the markup (the container, the class variants), the
  JS ops, and that the element the commands address, and the one the CSS looks at, is an
  ancestor of both the widget and the dock; not the survival across a navigation. That is
  LiveView's own behaviour.
  """

  alias Phoenix.LiveView.JS

  @target "body"
  @container_id "pk-dock"
  @open_class "pk-dock-open"
  @width_var "--pk-dock-width"

  @doc "The selector of the element the commands put the open class on."
  @spec target() :: String.t()
  def target, do: @target

  @doc "The id of the dock container."
  @spec container_id() :: String.t()
  def container_id, do: @container_id

  @doc "The class that opens the dock."
  @spec open_class() :: String.t()
  def open_class, do: @open_class

  @doc "The CSS variable that sets the dock's width."
  @spec width_var() :: String.t()
  def width_var, do: @width_var

  @doc "Open the dock."
  @spec open(JS.t()) :: JS.t()
  def open(js \\ %JS{}), do: JS.add_class(js, @open_class, to: @target)

  @doc "Close the dock."
  @spec close(JS.t()) :: JS.t()
  def close(js \\ %JS{}), do: JS.remove_class(js, @open_class, to: @target)

  @doc "Open the dock if it is closed, close it if it is open."
  @spec toggle(JS.t()) :: JS.t()
  def toggle(js \\ %JS{}), do: JS.toggle_class(js, @open_class, to: @target)
end
