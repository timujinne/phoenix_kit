defmodule PhoenixKit.MailerResolutionTest do
  @moduledoc """
  `Mailer.resolved_send_path/0` and `Config.mailer_local?/0` — the core of the
  issue #687 fix. Deliberately a plain `ExUnit.Case`, NOT `PhoenixKit.DataCase`:
  the logic is pure config resolution (the integration lookup short-circuits /
  rescues to `:error` with no reachable DB), and a DataCase module would be
  auto-tagged `:integration` and silently excluded on a database-less run,
  leaving the headline fix with zero executable coverage there.
  """
  # Mutates the global :phoenix_kit mailer config — must not interleave.
  use ExUnit.Case, async: false

  alias PhoenixKit.Mailer

  setup do
    prev_own = Application.get_env(:phoenix_kit, PhoenixKit.Mailer)
    prev_delegate = Application.get_env(:phoenix_kit, :mailer)

    on_exit(fn ->
      restore = fn
        _key, nil -> :ok
        key, val -> Application.put_env(:phoenix_kit, key, val)
      end

      Application.delete_env(:phoenix_kit, PhoenixKit.Mailer)
      Application.delete_env(:phoenix_kit, :mailer)
      restore.(PhoenixKit.Mailer, prev_own)
      restore.(:mailer, prev_delegate)
    end)

    :ok
  end

  defp put_host_mailer_env(adapter) do
    parent_app = PhoenixKit.Config.get_parent_app()
    prev = Application.get_env(parent_app, MailerResolutionHost)

    on_exit(fn ->
      if prev do
        Application.put_env(parent_app, MailerResolutionHost, prev)
      else
        Application.delete_env(parent_app, MailerResolutionHost)
      end
    end)

    Application.put_env(parent_app, MailerResolutionHost, adapter: adapter)
  end

  test "delegation mode resolves the HOST mailer's adapter (issue #687 false negative)" do
    put_host_mailer_env(Swoosh.Adapters.Local)
    Application.put_env(:phoenix_kit, :mailer, MailerResolutionHost)

    assert {:mailer, MailerResolutionHost, Swoosh.Adapters.Local} =
             Mailer.resolved_send_path()

    assert PhoenixKit.Config.mailer_local?()
  end

  test "installer Local block + delegating real host mailer is NOT local (the false positive)" do
    put_host_mailer_env(Swoosh.Adapters.SMTP)
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.Local)
    Application.put_env(:phoenix_kit, :mailer, MailerResolutionHost)

    assert {:mailer, MailerResolutionHost, Swoosh.Adapters.SMTP} =
             Mailer.resolved_send_path()

    refute PhoenixKit.Config.mailer_local?()
  end

  test "built-in mailer reads its own :phoenix_kit config" do
    Application.delete_env(:phoenix_kit, :mailer)
    Application.put_env(:phoenix_kit, PhoenixKit.Mailer, adapter: Swoosh.Adapters.Local)

    assert {:mailer, PhoenixKit.Mailer, Swoosh.Adapters.Local} = Mailer.resolved_send_path()
    assert PhoenixKit.Config.mailer_local?()
  end

  test "no adapter configured anywhere is not local" do
    Application.delete_env(:phoenix_kit, :mailer)
    Application.delete_env(:phoenix_kit, PhoenixKit.Mailer)

    assert {:mailer, PhoenixKit.Mailer, nil} = Mailer.resolved_send_path()
    refute PhoenixKit.Config.mailer_local?()
  end
end
