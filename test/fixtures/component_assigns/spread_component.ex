defmodule Fixture.Spread do
  @moduledoc false
  use Phoenix.Component

  attr(:label, :string, required: true)
  attr(:rest, :global)

  def button(assigns) do
    extra = assigns_to_attributes(assigns, [:label])
    assigns = assign(assigns, :extra, extra)

    ~H"<button {@extra}>{@label} {@who_knows}</button>"
  end
end
