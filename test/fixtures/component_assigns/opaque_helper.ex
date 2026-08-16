defmodule Fixture.OpaqueHelper do
  @moduledoc false
  use Phoenix.Component

  # The language-switcher shape: assigns pass through a local helper the
  # analysis cannot follow, so the component is skipped, not flagged.
  attr(:class, :string, default: nil)

  def dropdown(assigns) do
    assigns = prepare_assigns(assigns)

    ~H"<div class={@class}>{@computed_elsewhere} {@also_computed}</div>"
  end

  defp prepare_assigns(assigns), do: assign(assigns, :computed_elsewhere, 1)
end
