defmodule PhoenixKitWeb.Components.Core.Textarea do
  @moduledoc """
  Provides a default textarea UI component.
  """
  use Phoenix.Component

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
        class={[
          "textarea min-h-[6rem] w-full focus:textarea-primary",
          @errors != [] && "textarea-error",
          @class
        ]}
        {@rest}
      ><%= Phoenix.HTML.Form.normalize_value("textarea", @value) %></textarea>

      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end
end
