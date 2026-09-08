defmodule PhoenixKitWeb.Components.Core.AdminEditLink do
  @moduledoc """
  Renders the "Edit" link a host drops into a public page's layout to reach
  the matching admin page.

  Reads plain assigns — no scope check happens here. The gate lives in
  `PhoenixKitWeb.AdminEditHelper.assign_admin_edit/3`, the producer that sets
  `:admin_edit_url`/`:admin_edit_label`; this component only decides how to
  render them, and renders nothing when `:url` is `nil` (unauthenticated
  visitor, non-admin, or a page nobody called the producer for).

  ## Examples

      <.admin_edit_link url={assigns[:admin_edit_url]} label={assigns[:admin_edit_label]} />

      <.admin_edit_link
        url={assigns[:admin_edit_url]}
        label={assigns[:admin_edit_label]}
        variant={:menu_item}
      />
  """
  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKitWeb.Components.Core.Icon

  @doc """
  Renders an edit link into the matching admin page.

  ## Attributes

    * `:url` — the admin page path. Renders nothing when `nil` (default).
    * `:label` — link text. Defaults to gettext "Edit" when `nil`.
    * `:variant` — `:button` (default, a standalone outlined button) or
      `:menu_item` (a daisyUI `menu` `<li>`, for dropdowns like
      `PhoenixKitWeb.Components.UserDashboardNav.user_dropdown/1`).
    * `:class` — extra classes appended to the variant's base classes.
    * `:rest` — passed through to the underlying `<.link>`.
  """
  attr :url, :string, default: nil
  attr :label, :string, default: nil
  attr :variant, :atom, default: :button, values: [:button, :menu_item]
  attr :class, :any, default: nil
  attr :rest, :global

  def admin_edit_link(%{url: nil} = assigns) do
    ~H""
  end

  def admin_edit_link(%{variant: :button} = assigns) do
    ~H"""
    <.link navigate={@url} class={["btn btn-sm btn-outline gap-2", @class]} {@rest}>
      <Icon.icon name="hero-pencil-square" class="w-4 h-4" /> {@label || gettext("Edit")}
    </.link>
    """
  end

  def admin_edit_link(%{variant: :menu_item} = assigns) do
    ~H"""
    <li>
      <.link navigate={@url} class={["flex items-center gap-3", @class]} {@rest}>
        <Icon.icon name="hero-pencil-square" class="w-4 h-4" />
        <span>{@label || gettext("Edit")}</span>
      </.link>
    </li>
    """
  end
end
