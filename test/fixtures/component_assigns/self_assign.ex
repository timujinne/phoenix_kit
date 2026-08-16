defmodule Fixture.SelfAssign do
  @moduledoc false
  use Phoenix.Component

  attr(:templates, :list, required: true)

  def picker(assigns) do
    assigns =
      assigns
      |> assign(:selected, hd(assigns.templates))
      |> assign_new(:site_host, fn -> "example.com" end)
      |> assign(count: 1, extra: nil)

    ~H"<div>{@selected} {@site_host} {@count} {@extra}</div>"
  end
end
