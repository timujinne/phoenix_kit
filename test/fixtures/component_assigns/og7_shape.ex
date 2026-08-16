defmodule Fixture.Og7 do
  @moduledoc false
  use Phoenix.Component

  attr(:loading, :boolean, default: false)
  defp panel(assigns), do: ~H"<span>{@loading}</span>"

  attr(:selected, :boolean, required: true)

  def modal(assigns) do
    ~H"<div><.panel :if={@selected} loading={@missing} /></div>"
  end
end
