defmodule PhoenixKitWeb.Components.Core.Textarea do
  @moduledoc """
  Provides a default textarea UI component.
  """
  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.FormFieldLabel, only: [label: 1]
  import PhoenixKitWeb.Components.Core.FormFieldError, only: [error: 1]
  import PhoenixKitWeb.Components.Core.Input, only: [translate_error: 1]

  attr :field, Phoenix.HTML.FormField

  attr :id, :any, default: nil
  attr :name, :any
  attr :label, :string, default: nil
  attr :value, :any

  attr :errors, :list, default: []

  attr :class, :any,
    default: nil,
    doc:
      "extra classes merged onto the `<textarea>` element (e.g. `textarea-sm`, `min-h-[12rem]`)"

  attr :mentions, :boolean,
    default: false,
    doc:
      "offer `@` people and `#` records as the user types. Needs " <>
        "`use PhoenixKit.Mentions.Live` on the LiveView for the search handler; " <>
        "without JavaScript the field behaves exactly as it does today"

  attr :rest, :global,
    include: ~w(autocomplete cols maxlength disabled placeholder readonly required rows)

  def textarea(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    assigns
    |> assign(field: nil, id: assigns.id || field.id)
    # Mirror `<.input>` / `<.select>`: without this a field-bound textarea
    # silently renders no error text and never picks up `textarea-error`, so a
    # failing changeset looks like a form that just refuses to save.
    |> assign(:errors, Enum.map(field.errors, &translate_error(&1)))
    |> assign_new(:name, fn -> field.name end)
    |> assign_new(:value, fn -> field.value end)
    |> textarea()
  end

  def textarea(assigns) do
    # The site switch, checked at render: with mentions off the field is an
    # ordinary textarea again — no hook, no hint promising a feature that
    # would silently return nothing.
    assigns = assign(assigns, :mentions, assigns.mentions and PhoenixKit.Mentions.enabled?())

    ~H"""
    <div phx-feedback-for={@name}>
      <%!-- Required marker, kept in sync with `<.input>`. --%>
      <.label :if={@label && @label != ""} for={@id} class="label mb-2">
        {@label}<span
          :if={@rest[:required]}
          class="text-error ml-0.5"
          aria-hidden="true"
        >*</span>
      </.label>

      <textarea
        id={@id}
        name={@name}
        phx-hook={@mentions && "MentionInput"}
        class={[
          "textarea min-h-[6rem] w-full focus:textarea-primary",
          @errors != [] && "textarea-error",
          @class
        ]}
        {@rest}
      ><%= Phoenix.HTML.Form.normalize_value("textarea", @value) %></textarea>

      <p :if={@mentions} class="mt-1 text-xs opacity-50">
        {gettext("Type @ to mention someone, # to link a record.")}
      </p>

      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end
end
