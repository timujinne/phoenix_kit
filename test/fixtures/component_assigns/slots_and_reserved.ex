defmodule Fixture.Slots do
  @moduledoc false
  use Phoenix.Component

  attr(:title, :string, required: true)
  slot(:inner_block, required: true)
  slot(:footer)

  def card(assigns) do
    ~H"""
    <div id={@myself}>
      {@title}
      {render_slot(@inner_block)}
      {render_slot(@footer)}
    </div>
    """
  end
end
