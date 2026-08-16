defmodule PhoenixKitWeb.Components.Core.FormFieldLabel do
  @moduledoc """
  Provides a label UI component for form components.
  """
  use Phoenix.Component

  @doc """
  Renders a label.
  """
  attr :for, :string, default: nil
  attr :class, :string, default: nil
  slot :inner_block, required: true

  def label(assigns) do
    ~H"""
    <label for={@for} class={["label", @class]}>
      <span class="fieldset-legend font-semibold">
        {render_slot(@inner_block)}
      </span>
    </label>
    """
  end
end
