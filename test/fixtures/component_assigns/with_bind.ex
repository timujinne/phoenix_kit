defmodule Fixture.WithBind do
  @moduledoc false
  use Phoenix.Component

  # `assigns <- assign(...)` in a `with` binds the template's var exactly like
  # `=` — the collector must harvest from it, or @loaded is a false positive.
  attr(:source, :map, required: true)

  def panel(assigns) do
    with assigns <- assign(assigns, :loaded, true) do
      ~H"<div :if={@loaded}>{@source.name}</div>"
    end
  end
end
