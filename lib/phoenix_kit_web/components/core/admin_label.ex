defmodule PhoenixKitWeb.Components.Core.AdminLabel do
  @moduledoc """
  What the admin area is called, in the visitor's own language.

  One resolver for the two places core names the admin area — the chip beside
  the project name in the admin header (`PhoenixKitWeb.Components.LayoutWrapper`)
  and the admin entry in the account menu
  (`PhoenixKitWeb.Components.UserDashboardNav`) — so the header and the menu
  cannot disagree.

  ## Why presets rather than a text field

  A host that wants its admin area called something other than "Admin Panel"
  picks from a closed list (`PhoenixKit.Config.admin_label_presets/0`), and each
  entry is a `gettext/1` msgid translated in every shipped locale. So the
  rename survives translation: a German visitor reads "Arbeitsbereich" where an
  English one reads "Workspace".

  That is the whole reason the list is closed, and the reason this is not an
  operator field on `/admin/settings`. A free-typed string is ONE string — it
  shows to every visitor in every language. It remains available as
  `config :phoenix_kit, admin_panel_label: "Acme HQ"` for a brand name no
  preset covers, where the tradeoff is at least visible at the point of the
  decision.

  Unset, the name is derived from `:admin_path`, so `admin_path: "/backoffice"`
  gives a `/backoffice` URL *and* a "Backoffice" header with one key. See
  `PhoenixKit.Config.admin_panel_label/0` for the full resolution order.

  ## Adding a preset

  Add it to `@admin_label_presets` in `PhoenixKit.Config`, add the matching
  `preset_text/1` clause here, then `mix gettext.extract --merge` and translate
  the new msgid in all shipped locales. A preset that is not translated
  everywhere defeats the point of having presets at all.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.Config

  @doc """
  The admin area's name, ready to render.

  Always a binary — `PhoenixKit.Config.admin_panel_label/0` never returns `nil`.
  """
  @spec text() :: String.t()
  def text do
    case Config.admin_panel_label() do
      {:custom, value} -> value
      {:preset, preset} -> preset_text(preset)
    end
  end

  @doc """
  Renders one preset to translated text.

  Every clause is a literal `gettext/1` call so `mix gettext.extract` can see
  it — a lookup through a map or `String.to_existing_atom/1` would compile, and
  then quietly ship untranslated.
  """
  @spec preset_text(atom()) :: String.t()
  def preset_text(:admin_panel), do: gettext("Admin Panel")
  def preset_text(:dashboard), do: gettext("Dashboard")
  def preset_text(:backoffice), do: gettext("Backoffice")
  def preset_text(:console), do: gettext("Console")
  def preset_text(:control_panel), do: gettext("Control Panel")
  def preset_text(:workspace), do: gettext("Workspace")
  def preset_text(:portal), do: gettext("Portal")
  def preset_text(:my_account), do: gettext("My Account")
  def preset_text(:management), do: gettext("Management")
  def preset_text(:studio), do: gettext("Studio")
end
