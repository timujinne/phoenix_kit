defmodule PhoenixKitWeb.Live.Settings.SecurityGate do
  @moduledoc """
  The `settings.security` check of the settings pages that hold nothing else
  (Authorization, Website access).

  The admin `on_mount` already refuses the page to a scope without the key
  (`@admin_view_permissions`); this repeats the check on the server for every
  event, so a scope that loses the key mid-session — or a client sending events
  to a page it should not have — changes nothing.

      def mount(params, session, socket) do
        if SecurityGate.allowed?(socket),
          do: do_mount(params, session, SecurityGate.attach(socket)),
          else: {:ok, SecurityGate.refuse(socket)}
      end
  """
  use Gettext, backend: PhoenixKitWeb.Gettext

  import Phoenix.LiveView, only: [attach_hook: 4, put_flash: 3, redirect: 2]

  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes

  @key "settings.security"

  @doc "The sub-permission key these pages need."
  @spec key() :: String.t()
  def key, do: @key

  @doc "Whether the socket's scope holds `settings.security`."
  @spec allowed?(Phoenix.LiveView.Socket.t()) :: boolean()
  def allowed?(socket), do: Scope.can?(socket.assigns[:phoenix_kit_current_scope], @key)

  @doc "The mount-time refusal: back to Settings with an error."
  @spec refuse(Phoenix.LiveView.Socket.t()) :: Phoenix.LiveView.Socket.t()
  def refuse(socket) do
    socket
    |> put_flash(:error, gettext("You do not have permission to access this section."))
    |> redirect(to: Routes.path("/admin/settings"))
  end

  @doc "Refuses every event of the LiveView when `allowed?/1` is false."
  @spec attach(Phoenix.LiveView.Socket.t()) :: Phoenix.LiveView.Socket.t()
  def attach(socket), do: attach_hook(socket, :settings_security_gate, :handle_event, &gate/3)

  defp gate(_event, _params, socket) do
    if allowed?(socket) do
      {:cont, socket}
    else
      {:halt,
       put_flash(
         socket,
         :error,
         gettext("You do not have permission to change security settings")
       )}
    end
  end
end
