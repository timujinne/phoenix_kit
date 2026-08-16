defmodule Fixture.NoAttrs do
  @moduledoc false
  use Phoenix.Component

  # No attr/slot declarations: receives whatever callers pass. Judging it
  # needs call-site analysis this check does not do — skipped by policy.
  defp toolbar(assigns), do: ~H"<div>{@template} {@anything}</div>"

  def used, do: toolbar(%{})
end
