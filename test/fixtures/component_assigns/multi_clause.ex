defmodule Fixture.MultiClause do
  @moduledoc false
  use Phoenix.Component

  attr(:status, :string, required: true)

  def badge(%{status: "ok"} = assigns) do
    ~H"""
    <span class="ok">{@status}</span>
    """
  end

  def badge(assigns), do: ~H"<span>{@status}</span>"
end
