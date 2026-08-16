defmodule Fixture.Deprecated do
  @moduledoc false
  use Phoenix.Component

  # Phoenix keeps pending attrs across ANY module attribute; so must the
  # analyzer, or a @deprecated/@dialyzer between attr and def hides the
  # component entirely.
  attr(:label, :string, required: true)
  @deprecated "use new_badge/1"
  def old_badge(assigns), do: ~H"<span>{@label} {@missing}</span>"
end
