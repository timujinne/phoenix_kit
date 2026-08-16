defmodule Fixture.Merge do
  @moduledoc false
  use Phoenix.Component

  attr(:base, :map, required: true)

  def merged(assigns) do
    assigns = Map.merge(assigns, %{derived: assigns.base, flag: true})
    ~H"<div>{@derived} {@flag}</div>"
  end
end
