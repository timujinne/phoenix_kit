defmodule Fixture.Interp do
  @moduledoc false
  use Phoenix.Component

  # The clock-widget shape: an assign read from inside a string
  # interpolation in an attribute expression. Real code, must be scanned.
  attr(:deg, :integer, required: true)

  def hand(assigns) do
    ~H"""
    <g transform={"rotate(#{@other_deg} 50 50)"}></g>
    """
  end
end
