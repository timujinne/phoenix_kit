defmodule PhoenixKitWeb.Components.Core.StatCard do
  @moduledoc """
  Provides a statistics card UI component for dashboard metrics.

  This component renders a gradient card with an icon, main statistic value,
  title, and subtitle. Commonly used in admin dashboards to display KPIs
  and real-time statistics.
  """

  use Phoenix.Component

  @doc """
  Renders a statistics card with semantic background color.

  ## Examples

      <.stat_card
        value={@session_stats.total_active}
        title="Active Sessions"
        subtitle="Currently logged in"
      >
        <:icon>
          <.icon name="hero-signal" class="w-6 h-6" />
        </:icon>
      </.stat_card>

      <.stat_card
        color="primary"
        value={@stats.active_users}
        title="Active Users"
        subtitle="Currently online"
      >
        <:icon>
          <.icon name="hero-users" class="w-6 h-6" />
        </:icon>
      </.stat_card>

      <.stat_card
        color="success"
        compact={true}
        value={@stats.total_users}
        title="Total Users"
        subtitle="Registered accounts"
      >
        <:icon>
          <.icon name="hero-check-circle" class="w-5 h-5" />
        </:icon>
      </.stat_card>
  """
  attr :rounded, :string,
    default: "box",
    values: ["box", "none", "sm", "md", "lg", "xl", "2xl", "3xl", "full"],
    doc:
      "Border radius. Was previously declared but ignored — the class was hardcoded. " <>
        "The values are a fixed list because Tailwind scans SOURCE for literal class " <>
        "names: an interpolated class is invisible to it, so the CSS " <>
        "would simply not exist for anything not already written literally elsewhere."

  attr :compact, :boolean, default: false, doc: "Use compact layout with reduced height"
  attr :value, :any, required: true, doc: "The main statistic value to display"
  attr :title, :string, required: true, doc: "The card title text"
  attr :subtitle, :string, required: true, doc: "The smaller descriptive text"

  attr :color, :string,
    default: "info",
    values: ["info", "primary", "success", "secondary", "warning", "error", "accent", "neutral"],
    doc:
      "Background color theme (info, primary, success, secondary, warning, error, accent, neutral)"

  attr :value_color, :string,
    default: nil,
    doc:
      "Optional CSS color for the value itself — for values whose color IS information " <>
        "(a price colored by cheapness, a temperature by severity). E.g. \"hsl(140 85% 55%)\". " <>
        "Any `;` is stripped so the value cannot append further declarations; every " <>
        "legitimate colour syntax (hsl/oklch/var/color-mix) is unaffected."

  attr :navigate, :string,
    default: nil,
    doc:
      "Optional destination. When set the whole card becomes a link to the report behind " <>
        "the number — a statistic a reader cannot drill into is a dead end. Pass a path " <>
        "already built through `PhoenixKit.Utils.Routes.path/1`; only pass one when a real " <>
        "report exists, since a link to a list that does not contain the counted rows is " <>
        "worse than no link."

  slot :icon, required: true, doc: "Icon to display in the card header"

  def stat_card(assigns) do
    ~H"""
    <%= if @navigate do %>
      <.link
        navigate={@navigate}
        class="block focus:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-box"
      >
        <.stat_card_body {assigns} />
      </.link>
    <% else %>
      <.stat_card_body {assigns} />
    <% end %>
    """
  end

  attr :rounded, :string, default: "box"
  attr :compact, :boolean, default: false
  attr :value, :any, required: true
  attr :title, :string, required: true
  attr :subtitle, :string, required: true
  attr :color, :string, default: "info"
  attr :value_color, :string, default: nil
  attr :navigate, :string, default: nil
  # NOT `required: true`: the slot arrives through `{assigns}` from the public
  # component, which the compiler cannot see statically. `stat_card/1` already
  # enforces it.
  slot :icon

  defp stat_card_body(assigns) do
    ~H"""
    <div class={[
      color_classes(@color),
      rounded_class(@rounded),
      "shadow-xl hover:shadow-2xl transition-all duration-300 transform hover:scale-105",
      @navigate && "cursor-pointer",
      if(@compact, do: "p-4", else: "p-6")
    ]}>
      <%= if @compact do %>
        <%!-- Compact horizontal layout --%>
        <div class="flex items-center gap-3">
          <div class="p-2 bg-white/20 rounded-box flex-shrink-0">
            {render_slot(@icon)}
          </div>
          <div class="flex-1">
            <div class="text-2xl font-bold mb-1" {value_style(@value_color)}>
              {@value}
            </div>
            <div class="opacity-90 font-medium text-sm">{@title}</div>
            <div class="opacity-70 text-xs">{@subtitle}</div>
          </div>
        </div>
      <% else %>
        <%!-- Original vertical layout --%>
        <div class="flex items-center justify-between mb-4">
          <div class="p-2 bg-white/20 rounded-box">
            {render_slot(@icon)}
          </div>
        </div>
        <div class="text-3xl font-bold mb-2" {value_style(@value_color)}>
          {@value}
        </div>
        <div class="opacity-90 font-medium">{@title}</div>
        <div class="opacity-70 text-xs mt-1">
          {@subtitle}
        </div>
      <% end %>
    </div>
    """
  end

  # Written out in full so Tailwind's content scanner can see every one of
  # them. Interpolating the token produces a class that exists in the markup
  # but never in the stylesheet.
  defp rounded_class("box"), do: "rounded-box"
  defp rounded_class("none"), do: "rounded-none"
  defp rounded_class("sm"), do: "rounded-sm"
  defp rounded_class("md"), do: "rounded-md"
  defp rounded_class("lg"), do: "rounded-lg"
  defp rounded_class("xl"), do: "rounded-xl"
  defp rounded_class("2xl"), do: "rounded-2xl"
  defp rounded_class("3xl"), do: "rounded-3xl"
  defp rounded_class("full"), do: "rounded-full"
  defp rounded_class(_), do: "rounded-box"

  # Color class helpers
  defp color_classes("info"), do: "bg-info text-info-content"
  defp color_classes("primary"), do: "bg-primary text-primary-content"
  defp color_classes("success"), do: "bg-success text-success-content"
  defp color_classes("secondary"), do: "bg-secondary text-secondary-content"
  defp color_classes("warning"), do: "bg-warning text-warning-content"
  defp color_classes("error"), do: "bg-error text-error-content"
  defp color_classes("accent"), do: "bg-accent text-accent-content"
  defp color_classes("neutral"), do: "bg-neutral text-neutral-content"
  defp color_classes(_), do: "bg-info text-info-content"

  # Returned as a spreadable attribute list rather than a `style={...}` value:
  # HEEx renders a nil attribute value as `style=""` instead of dropping it, so
  # every unstyled card carried an empty attribute.
  #
  # The colour is usually computed (a price coloured by cheapness), so it is
  # kept to a single declaration — one stray `;` would otherwise let the value
  # write arbitrary CSS onto the element. Colour functions contain no
  # semicolons, so hsl()/oklch()/var()/color-mix() pass through untouched.
  defp value_style(nil), do: []

  defp value_style(color) do
    case color |> to_string() |> String.replace(";", "") |> String.trim() do
      "" -> []
      clean -> [style: "color: " <> clean]
    end
  end
end
