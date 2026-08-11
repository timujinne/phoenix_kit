defmodule PhoenixKit.Integration.DevMailboxToggleTest do
  # Mutates global :phoenix_kit mailer config — must not interleave.
  use PhoenixKitWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.RoleAssignment
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  defp unique_email, do: "mailbox_#{System.unique_integer([:positive])}@example.com"

  # `Roles.assign_role/3` refuses the Owner role by design, so insert it.
  defp owner_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    owner_role = Roles.get_role_by_name("Owner")

    {:ok, _} =
      %RoleAssignment{}
      |> RoleAssignment.changeset(%{user_uuid: user.uuid, role_uuid: owner_role.uuid})
      |> Repo.insert(on_conflict: :nothing, conflict_target: [:user_uuid, :role_uuid])

    Repo.get!(Auth.User, user.uuid)
  end

  setup %{conn: conn} do
    prev_own = Application.get_env(:phoenix_kit, PhoenixKit.Mailer)
    prev_delegate = Application.get_env(:phoenix_kit, :mailer)
    Application.delete_env(:phoenix_kit, :mailer)
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.Local)

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, PhoenixKit.Mailer)
      Application.delete_env(:phoenix_kit, :mailer)
      if prev_own, do: Application.put_env(:phoenix_kit, PhoenixKit.Mailer, prev_own)
      if prev_delegate, do: Application.put_env(:phoenix_kit, :mailer, prev_delegate)
      # The sandbox rolls the settings row back, but the app-supervised ETS
      # cache is not transactional — drop the key so the rolled-back "true"
      # cannot leak into another module's gate-closed assertions.
      PhoenixKit.Cache.invalidate(:settings, "dev_mailbox_enabled")
    end)

    %{conn: log_in_user(conn, owner_user())}
  end

  test "section renders with the log-info banner and flips the setting", %{conn: conn} do
    {:ok, view, html} = live(conn, Routes.path("/admin/settings/email-sending"))

    assert html =~ "Local dev mailbox"
    assert html =~ "written to the server log"

    view
    |> form("#dev-mailbox-form", %{"enabled" => "true"})
    |> render_change()

    assert PhoenixKit.Settings.get_setting("dev_mailbox_enabled") == "true"
    assert render(view) =~ "Only for closed environments"
  end

  test "section hidden when the resolved path is not local", %{conn: conn} do
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.SMTP)

    {:ok, _view, html} = live(conn, Routes.path("/admin/settings/email-sending"))
    refute html =~ "Local dev mailbox"
  end
end
