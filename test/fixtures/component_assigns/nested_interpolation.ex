defmodule Fixture.NestedInterp do
  @moduledoc false
  use Phoenix.Component

  # An interpolation inside a string inside an interpolation inside an
  # attribute expression — every read in the chain is real.
  attr(:label, :string, required: true)

  def chip(assigns) do
    ~H"""
    <div class={"#{if @selected, do: "bg-#{@variant}-500"}"}>{@label}</div>
    """
  end
end
