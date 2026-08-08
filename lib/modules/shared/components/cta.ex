defmodule PhoenixKit.Modules.Shared.Components.CTA do
  @moduledoc """
  Call-to-action button component.

  Rendered inside a centring block. The button itself shrinks to its content,
  so left in the flow it sits flush against the left margin of the text
  column — which reads as a mistake for something whose whole job is to be
  the one thing you look at.
  """
  use Phoenix.Component

  attr :content, :string, required: true
  attr :attributes, :map, default: %{}
  attr :variant, :string, default: "default"

  def render(assigns) do
    is_primary = Map.get(assigns.attributes, "primary", "false") == "true"
    action = Map.get(assigns.attributes, "action", "")

    assigns =
      assigns
      |> assign(:is_primary, is_primary)
      # "#" is not a destination — it is a link to the top of the page. A CTA
      # with nothing to point at should look like a button and do nothing, not
      # silently scroll the reader away from what they were reading.
      |> assign(:action, if(action in ["", "#"], do: nil, else: action))

    ~H"""
    <div class="my-6 text-center">
      <a
        href={@action}
        class={[
          "btn px-8 py-3 rounded-lg font-semibold transition-all",
          if(@is_primary,
            do: "btn-primary text-primary-content",
            else: "btn-outline"
          )
        ]}
      >
        {@content}
      </a>
    </div>
    """
  end
end
