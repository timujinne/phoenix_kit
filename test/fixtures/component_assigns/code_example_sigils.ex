defmodule Fixture.CodeExamples do
  @moduledoc false
  use Phoenix.Component

  # A component-showcase page printing template snippets as literal text —
  # prose about code, not reads.
  attr(:heading, :string, required: true)

  def form_helpers_section(assigns) do
    ~H"""
    <div>
      <h2>{@heading}</h2>
      <code>{~s|<.simple_form for={@form} phx-submit="save">|}</code>
      <code>{~s|<.nav_tabs active_tab={@tab} on_change="switch_tab" />|}</code>
      <code>{~s(<dialog class={["modal", @show && "modal-open"]}>)}</code>
    </div>
    """
  end
end
