defmodule PhoenixKitWeb.Components.Core.DevNoticeTest do
  # Mutates global :phoenix_kit mailer config.
  use ExUnit.Case, async: false

  import Phoenix.LiveViewTest

  alias PhoenixKitWeb.Components.Core.DevNotice

  setup do
    prev_own = Application.get_env(:phoenix_kit, PhoenixKit.Mailer)
    prev_delegate = Application.get_env(:phoenix_kit, :mailer)
    Application.delete_env(:phoenix_kit, :mailer)

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, PhoenixKit.Mailer)
      Application.delete_env(:phoenix_kit, :mailer)
      if prev_own, do: Application.put_env(:phoenix_kit, PhoenixKit.Mailer, prev_own)
      if prev_delegate, do: Application.put_env(:phoenix_kit, :mailer, prev_delegate)
    end)

    :ok
  end

  defp render_notice do
    render_component(&DevNotice.dev_mailbox_notice/1, %{})
  end

  test "does not render when the resolved mailer is not local" do
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.SMTP)
    refute render_notice() =~ "Development mode"
  end

  test "gate closed: points at the server log, never links the mailbox" do
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.Local)
    html = render_notice()
    assert html =~ "written to the server log"
    refute html =~ "/dev/mailbox"
  end

  # The gate-open variant needs the settings row in the DB and is covered by
  # the email-sending LV test (dev_mailbox_toggle_test.exs); here we pin the
  # DB-less default, which must read as "closed".
end
