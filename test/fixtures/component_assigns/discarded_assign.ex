defmodule Fixture.Discarded do
  @moduledoc false
  use Phoenix.Component

  # The result of assign/3 is discarded, so :ready never reaches the
  # template's assigns — @ready is a real KeyError, and a collector that
  # harvests keys from calls instead of rebinds hides it.
  attr(:title, :string, required: true)

  def card(assigns) do
    _ = assign(assigns, :ready, true)

    ~H"""
    <div :if={@ready}>{@title}</div>
    """
  end
end
