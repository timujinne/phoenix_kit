defmodule PhoenixKitWeb.Components.Core.Button do
  @moduledoc """
  Provides a button UI component.

  ## Adopting this in a host app

  A `mix phx.new` app already has its own `button/1` in `CoreComponents`. Both
  names are in scope once you import this one, and no change here resolves that
  — the ambiguity is the name plus the import, not the body. Pick one:

      import MyAppWeb.CoreComponents, except: [button: 1]

  or delete your scaffold's version. Host LiveViews receive nothing from
  PhoenixKit automatically; importing is a deliberate step.
  """

  use Phoenix.Component

  @doc """
  Renders a button, or a link styled as one when given a navigation attribute.

  ## Examples

      <.button>Send!</.button>
      <.button phx-click="go" class="ml-2">Send!</.button>
      <.button variant="ghost" size="sm">Cancel</.button>
      <.button navigate={~p"/users/new"}>New user</.button>

  ## Variants

  `variant` REPLACES the base colour rather than adding to it. It used to
  append: the class list hardcoded `btn-primary`, so `class="btn-ghost"` left
  both on the element and daisyUI's rule ordering decided the winner.

  The kit's set — not the scaffold's `values: ~w(primary)`, a knob that
  cannot vary. Status colours (`info` / `success` / `warning` / `error`)
  are first-class variants: passing `class="btn-error"` next to the
  default `btn-primary` is how stylesheet order used to pick the winner.

  Variant and size map to literal classes rather than interpolating
  `"btn-\#{@variant}"`, because Tailwind scans **source** for literal class
  names — an interpolated class is invisible to it and the CSS would simply not
  exist unless something else in the codebase happened to write it out.
  """
  attr :type, :string, default: nil

  attr :variant, :string,
    default: "primary",
    values: ~w(primary secondary accent neutral ghost link outline info success warning error),
    doc: "Base colour. Replaces the default; use `class` for anything outside this set."

  attr :size, :string,
    default: nil,
    values: [nil | ~w(xs sm md lg)],
    doc: "daisyUI button size. Omitted leaves daisyUI's default."

  attr :navigate, :string,
    default: nil,
    doc: "Renders a `<.link navigate=…>` instead of a button."

  attr :patch, :string, default: nil, doc: "Renders a `<.link patch=…>` instead of a button."
  attr :href, :any, default: nil, doc: "Renders a `<.link href=…>` instead of a button."

  # `:any`, not `:string`, for scaffold parity — a list of classes is idiomatic
  # in HEEx and would fail attr validation as a string.
  attr :class, :any, default: nil

  attr :rest, :global, include: ~w(disabled form name value download target rel method)

  slot :inner_block, required: true

  def button(%{navigate: nil, patch: nil, href: nil} = assigns) do
    ~H"""
    <button type={@type} class={button_class(@variant, @size, @class)} {@rest}>
      {render_slot(@inner_block)}
    </button>
    """
  end

  # `table_default`'s own docs have shown `<.button size="sm" navigate={~p"/…"}>`
  # for a while. Neither attribute was declared, so `navigate` was silently
  # dropped and copying the documented example produced a dead control.
  def button(assigns) do
    ~H"""
    <.link
      navigate={@navigate}
      patch={@patch}
      href={@href}
      class={button_class(@variant, @size, @class)}
      {@rest}
    >
      {render_slot(@inner_block)}
    </.link>
    """
  end

  defp button_class(variant, size, class) do
    ["btn", variant_class(variant), size_class(size), "phx-submit-loading:opacity-75", class]
  end

  defp variant_class("primary"), do: "btn-primary"
  defp variant_class("secondary"), do: "btn-secondary"
  defp variant_class("accent"), do: "btn-accent"
  defp variant_class("neutral"), do: "btn-neutral"
  defp variant_class("ghost"), do: "btn-ghost"
  defp variant_class("link"), do: "btn-link"
  defp variant_class("outline"), do: "btn-outline"
  # The status half of daisyUI's palette — hosts previously had to fall back
  # to raw <button> markup for a delete button, because appending btn-error
  # via `class` collides with the variant's own colour class and stylesheet
  # order decides who wins.
  defp variant_class("info"), do: "btn-info"
  defp variant_class("success"), do: "btn-success"
  defp variant_class("warning"), do: "btn-warning"
  defp variant_class("error"), do: "btn-error"
  defp variant_class(_), do: "btn-primary"

  defp size_class("xs"), do: "btn-xs"
  defp size_class("sm"), do: "btn-sm"
  defp size_class("md"), do: "btn-md"
  defp size_class("lg"), do: "btn-lg"
  defp size_class(_), do: nil
end
