defmodule PhoenixKitWeb.Components.Core.FormSection do
  @moduledoc """
  Card-wrapped form section with a titled header.

  Replaces the repeated boilerplate:

      <div class="card bg-base-100 shadow-lg">
        <div class="card-body">
          <h2 class="card-title text-lg">Section Name</h2>
          ...fields...
        </div>
      </div>

  with a single component call. Used in every form-heavy admin page.

  ## Attributes

  - `title` — Section heading text. Required.
  - `icon` — Optional Heroicon name rendered before the title (e.g.
    `"hero-cog-6-tooth"`).
  - `class` — Extra classes appended to the outer card wrapper.
  - `body_class` — Extra classes appended to the card body wrapper
    (typical use: `"space-y-4"` for vertical field spacing).
  - `wrap_actions` — Let the `:actions` drop under the title when the row
    has no room for both. Off by default.

  ## Slots

  - `inner_block` — Section content (form fields). Required.
  - `:subtitle` — Optional helper text rendered under the title. Slot
    (not attr) so callers can drop a `<.pk_link>` / `<.icon>` / etc.
    inline.
  - `:actions` — Optional controls on the right of the title row (e.g. a
    "Reset to defaults" button). Without it the title renders exactly as
    before.

  ## Example

      <.form_section title={gettext("Provider Configuration")}>
        <:subtitle>
          {gettext("Credentials live in")}
          <.pk_link navigate="/admin/settings/integrations" class="link link-primary">
            Settings → Integrations
          </.pk_link>.
        </:subtitle>
        <.select field={@form[:provider]} ... />
      </.form_section>

      <.form_section title={gettext("Basic Information")} body_class="space-y-4">
        <.input field={@form[:name]} label="Name" required />
      </.form_section>
  """

  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.Icon, only: [icon: 1]

  attr :title, :string,
    default: nil,
    doc:
      "The card's heading. Optional: a card holding a single form (a page's " <>
        "only section) reads fine without one, and no empty heading row is drawn."

  attr :icon, :string, default: nil
  attr :class, :string, default: nil
  attr :body_class, :string, default: nil
  attr :rest, :global

  attr :wrap_actions, :boolean,
    default: false,
    doc:
      "Let the `:actions` drop under the title when the row has no room for both (a long button label on a narrow screen), instead of pushing the card wider than the screen."

  slot :inner_block, required: true
  slot :subtitle

  slot :actions,
    doc: "Controls on the right of the title row, e.g. a \"Reset to defaults\" button."

  def form_section(assigns) do
    ~H"""
    <section class={["card bg-base-100 shadow-lg", @class]} {@rest}>
      <div class={["card-body", @body_class]}>
        <div
          :if={@actions != []}
          class={
            if @wrap_actions,
              do: "flex flex-wrap items-start justify-between gap-3",
              else: "flex items-start justify-between gap-3"
          }
        >
          <h2 :if={@title} class="card-title text-lg">
            <.icon :if={@icon} name={@icon} class="w-5 h-5" /> {@title}
          </h2>
          <div :if={!@title}></div>
          <div class="shrink-0 flex items-center gap-2">{render_slot(@actions)}</div>
        </div>
        <h2 :if={@actions == [] and @title} class="card-title text-lg">
          <.icon :if={@icon} name={@icon} class="w-5 h-5" /> {@title}
        </h2>
        <p :if={@subtitle != []} class="text-sm text-base-content/60 -mt-1">
          {render_slot(@subtitle)}
        </p>
        {render_slot(@inner_block)}
      </div>
    </section>
    """
  end

  @doc """
  Lightweight in-card section heading — groups related fields inside one
  form/card without the full `form_section` card wrapper (icon + title + rule).
  Used by the settings pages (General, Authorization).
  """
  attr :icon, :string, required: true
  attr :title, :string, required: true
  attr :class, :string, default: nil

  slot :actions, doc: "optional right-aligned controls (e.g. an Add button)"

  def section_header(assigns) do
    ~H"""
    <div class={["flex items-center gap-2 pt-4 first:pt-0", @class]}>
      <.icon name={@icon} class="w-4 h-4 text-primary/70" />
      <h3 class="text-sm font-semibold uppercase tracking-wide text-base-content/60">
        {@title}
      </h3>
      <div class="flex-1 border-t border-base-300 ml-2"></div>
      <div :if={@actions != []} class="shrink-0">{render_slot(@actions)}</div>
    </div>
    """
  end

  @doc """
  Per-field dirty indicator: renders only when the pending value differs from
  the saved one, showing what's currently saved. Replaces always-on
  "Saved: X | Selected: Y" echoes so clean fields carry no noise.
  """
  attr :dirty, :boolean, required: true
  attr :saved, :string, default: nil

  def unsaved_hint(assigns) do
    ~H"""
    <div :if={@dirty} class="label pt-1">
      <span class="fieldset-label text-xs text-warning flex items-center gap-1.5">
        <.icon name="hero-pencil-square" class="w-3.5 h-3.5" />
        {gettext("Unsaved change")}
        <span :if={(@saved || "") != ""} class="text-base-content/40">
          — {gettext("saved:")} {@saved}
        </span>
      </span>
    </div>
    """
  end
end
