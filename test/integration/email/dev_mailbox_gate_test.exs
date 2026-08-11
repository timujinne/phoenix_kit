defmodule PhoenixKit.Integration.DevMailboxGateTest do
  # Mutates global :phoenix_kit mailer config and the shared Local mailbox
  # storage — must not interleave with other tests.
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog

  alias Swoosh.Adapters.Local.Storage.Memory

  setup do
    prev_own = Application.get_env(:phoenix_kit, PhoenixKit.Mailer)
    prev_delegate = Application.get_env(:phoenix_kit, :mailer)
    Application.delete_env(:phoenix_kit, :mailer)
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.Local)

    # Swoosh 1.x registers the storage globally and exposes start/1 (unlinked),
    # not start_link/1 — start_supervised!/1 cannot manage it.
    started_storage =
      case :global.whereis_name(Memory) do
        :undefined ->
          {:ok, _pid} = Memory.start()
          true

        _pid ->
          false
      end

    Memory.delete_all()

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, PhoenixKit.Mailer)
      Application.delete_env(:phoenix_kit, :mailer)
      if prev_own, do: Application.put_env(:phoenix_kit, PhoenixKit.Mailer, prev_own)
      if prev_delegate, do: Application.put_env(:phoenix_kit, :mailer, prev_delegate)
      if started_storage, do: Memory.stop()
      # The sandbox rolls the settings row back, but the app-supervised ETS
      # cache is not transactional — drop the key so the rolled-back "true"
      # cannot leak into another module's gate-closed assertions.
      PhoenixKit.Cache.invalidate(:settings, "dev_mailbox_enabled")
    end)

    email =
      Swoosh.Email.new(
        to: "dev@example.com",
        from: "noreply@example.com",
        subject: "Reset instructions",
        text_body: "Reset link: http://localhost:4000/users/reset-password/TOKEN"
      )

    %{email: email}
  end

  test "gate closed by default: nothing reaches the mailbox, the mail is logged", %{email: email} do
    log =
      capture_log(fn ->
        assert {:ok, %{suppressed: true}} = PhoenixKit.Mailer.deliver_email(email)
      end)

    assert Memory.all() == []
    assert log =~ "reset-password/TOKEN"
    assert log =~ "/admin/settings/email-sending"
  end

  test "gate opened via the setting: the mailbox receives the message", %{email: email} do
    {:ok, _} = PhoenixKit.Settings.update_setting("dev_mailbox_enabled", "true")

    assert {:ok, _meta} = PhoenixKit.Mailer.deliver_email(email)
    assert [%Swoosh.Email{subject: "Reset instructions"}] = Memory.all()
  end

  test "default settings carry the key off" do
    assert PhoenixKit.Settings.get_defaults()["dev_mailbox_enabled"] == "false"
  end
end
