defmodule PhoenixKitWeb.Components.Core.Select do
  @moduledoc """
  Provides a default select UI component.
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
  attr :options, :list
  attr :multiple, :boolean, default: false
  attr :prompt, :string, default: nil

  attr :errors, :list, default: []

  attr :class, :any,
    default: nil,
    doc:
      "extra classes merged onto the daisyUI `<label class=\"select\">` wrapper — use this for daisyUI modifiers like `select-sm`, `select-primary`, or project-specific focus styles like `transition-colors focus-within:select-primary`"

  attr :rest, :global,
    include: ~w(autocomplete cols maxlength disabled placeholder readonly required rows)

  def select(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    assigns
    |> assign(field: nil, id: assigns.id || field.id)
    |> assign(:errors, Enum.map(field.errors, &translate_error(&1)))
    |> assign_new(:name, fn -> field.name end)
    |> assign_new(:value, fn -> field.value end)
    |> select()
  end

  def select(assigns) do
    ~H"""
    <div phx-feedback-for={@name}>
      <%!-- Required marker, kept in sync with `<.input>` — a `required` select
           whose label came from the caller used to lose the red asterisk the
           hand-rolled markup had. --%>
      <.label :if={@label && @label != ""} for={@id} class="block mb-2">
        {@label}<span
          :if={@rest[:required]}
          class="text-error ml-0.5"
          aria-hidden="true"
        >*</span>
      </.label>

      <label class={[
        "select w-full",
        @errors != [] && "select-error",
        @class
      ]}>
        <select
          id={@id}
          name={@name}
          multiple={@multiple}
          {@rest}
        >
          <option :if={@prompt} value="">{@prompt}</option>
          {Phoenix.HTML.Form.options_for_select(@options, @value)}
        </select>
      </label>

      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end
end
