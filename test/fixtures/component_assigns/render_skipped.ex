defmodule Fixture.RenderSkipped do
  @moduledoc false
  use Phoenix.Component

  attr(:unrelated, :string)
  def render(assigns), do: ~H"<div>{@socket_assign} {@from_mount}</div>"
end
