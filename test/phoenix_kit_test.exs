defmodule PhoenixKitTest.UnreadableKeyStore do
  @behaviour PhoenixKit.Integrations.KeyStore

  @impl true
  def read(_opts), do: {:error, :unreadable_for_test}

  @impl true
  def write(_secret, _opts), do: :ok

  @impl true
  def preflight(_opts), do: :ok

  @impl true
  def describe(_opts), do: "/unreadable/store.key"
end

defmodule PhoenixKitTest do
  use ExUnit.Case

  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Integrations.KeyStore
  alias PhoenixKit.Migrations.Postgres, as: Migrations

  @moduledoc """
  Basic smoke tests for PhoenixKit library.

  PhoenixKit is a library module designed to be integrated into Phoenix applications.
  These tests verify that core modules are loadable and properly configured.

  Comprehensive testing should be performed in the context of a parent Phoenix
  application where database, configuration, and runtime dependencies are available.
  """

  describe "PhoenixKit module" do
    test "module is defined and loadable" do
      assert Code.ensure_loaded?(PhoenixKit)
    end

    test "version is defined" do
      # Verify the version constant exists in mix.exs
      mix_config = Mix.Project.config()
      version = mix_config[:version]

      assert is_binary(version)
      assert String.match?(version, ~r/^\d+\.\d+\.\d+/)
    end

    test "application is properly configured" do
      assert Application.get_application(PhoenixKit) == :phoenix_kit
    end
  end

  describe "Core modules" do
    test "RepoHelper module is defined" do
      assert Code.ensure_loaded?(PhoenixKit.RepoHelper)
    end

    test "Users.Auth module is defined" do
      assert Code.ensure_loaded?(PhoenixKit.Users.Auth)
    end

    test "User schema is defined" do
      assert Code.ensure_loaded?(PhoenixKit.Users.Auth.User)
    end

    test "Settings module is defined" do
      assert Code.ensure_loaded?(PhoenixKit.Settings)
    end

    test "Migrations.Postgres module is defined" do
      assert Code.ensure_loaded?(PhoenixKit.Migrations.Postgres)
    end
  end

  describe "Migration system" do
    test "initial version is the squash floor and matches the oldest module on disk" do
      # The chain was consolidated at floor 135: v01..v134 are gone and V135 is
      # the baseline, so initial_version/0 is no longer 1. Deriving the
      # expectation from disk rather than hardcoding keeps this honest across a
      # future re-squash.
      oldest_on_disk =
        "lib/phoenix_kit/migrations/postgres/v*.ex"
        |> Path.wildcard()
        |> Enum.map(
          &(&1
            |> Path.basename(".ex")
            |> String.trim_leading("v")
            |> String.to_integer())
        )
        |> Enum.min()

      assert Migrations.initial_version() == oldest_on_disk
      assert Migrations.initial_version() > 1
    end

    test "current version is defined and valid" do
      current = Migrations.current_version()
      initial = Migrations.initial_version()

      assert is_integer(current)
      assert current >= initial
      # Current version should be at least V15 as of 1.2.13
      assert current >= 15
    end
  end

  describe "boot/1" do
    test "{:ok, pid} input is returned unchanged and triggers registry rescan" do
      # We use a real pid (self()) — `boot/1` doesn't inspect it, only the
      # outer tuple shape. Calling it should also be safe with the live
      # registry: `rescan/0` returns `{:ok, []}` and `run_all_legacy_migrations/0`
      # is idempotent.
      pid = self()
      assert {:ok, ^pid} = PhoenixKit.boot({:ok, pid})
    end

    test "{:error, reason} short-circuits and returns input unchanged" do
      # On supervisor failure we MUST NOT run rescan or migrations on a
      # half-started system. The error tuple passes through verbatim.
      assert {:error, :supervisor_failed} = PhoenixKit.boot({:error, :supervisor_failed})
    end
  end

  describe "boot/1 — integrations encryption boot check" do
    import ExUnit.CaptureLog

    setup do
      original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
      original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

      original_warn_on_boot =
        Application.get_env(:phoenix_kit, :integration_encryption_warn_on_boot)

      on_exit(fn ->
        restore_env(:integrations_encryption_key, original_dedicated)
        restore_env(:secret_key_base, original_flat)
        restore_env(:integration_encryption_warn_on_boot, original_warn_on_boot)
      end)

      :ok
    end

    # Off by default: an install still on the legacy secret_key_base fallback
    # (the common, supported case — see `Encryption`'s moduledoc) must not get
    # this log line on every single restart with no way to quiet it.
    # `mix phoenix_kit.doctor` and the admin system page still surface the
    # same diagnosis on demand — this only silences the boot-time push.
    test "does not warn about the legacy key tier by default" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.put_env(:phoenix_kit, :secret_key_base, "legacy-secret-for-boot-test")
      Application.delete_env(:phoenix_kit, :integration_encryption_warn_on_boot)

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      refute log =~ "[PhoenixKit.Integrations]"
    end

    test "does not warn about the legacy key tier when warn_on_boot is explicitly false" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.put_env(:phoenix_kit, :secret_key_base, "legacy-secret-for-boot-test")
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, false)

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      refute log =~ "[PhoenixKit.Integrations]"
    end

    # The flag covers the boot REPORT for every state where encryption works,
    # not only the legacy key: a dedicated key whose key store cannot be read is
    # a warning too, and it is off by default for the same reason. It does not
    # cover the one-time "key store could not be read" error: `boot/1` always
    # resolves the key, and that error is logged by the resolution itself. The
    # one-time flag and the key-store cache are reset before every boot so the
    # assertions see what a fresh VM would log.
    test "a key-store problem under a dedicated key: the report needs warn_on_boot, the read error does not" do
      original_store = Application.get_env(:phoenix_kit, :integrations_key_store)

      reset_once_state = fn ->
        :persistent_term.erase({Encryption, :store_failure_logged})
        KeyStore.invalidate_cache()
      end

      on_exit(fn ->
        restore_env(:integrations_key_store, original_store)
        reset_once_state.()
      end)

      Application.put_env(
        :phoenix_kit,
        :integrations_encryption_key,
        "a-dedicated-key-well-over-the-minimum-length"
      )

      Application.put_env(
        :phoenix_kit,
        :integrations_key_store,
        {PhoenixKitTest.UnreadableKeyStore, []}
      )

      reset_once_state.()
      {report, _log} = with_log(fn -> Encryption.key_report() end)
      assert report.diagnosis == {:dedicated, :store_unreadable}
      report_line = Encryption.key_report_message(report)

      # Flag off: no report line, but the one-time read error is there.
      Application.delete_env(:phoenix_kit, :integration_encryption_warn_on_boot)
      reset_once_state.()
      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      refute log =~ report_line
      assert log =~ "A key store IS configured but its secret could not be read"

      # Flag on: the report line as well.
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, true)
      reset_once_state.()
      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      assert log =~ report_line
    end

    # This check used to run as a `Task` child of `PhoenixKit.Supervisor`,
    # which commonly starts BEFORE the host app's own Endpoint — at that
    # point `Encryption.status/0`'s Endpoint lookup can't resolve yet, so
    # an install relying on the (supported, common) secret_key_base
    # fallback would misreport as `:disabled_no_key` instead of
    # `:legacy_secret_key_base`. `boot/1` runs only after
    # `Supervisor.start_link/2` returns, i.e. after the host's Endpoint has
    # definitely started — this proves the check is wired in here and
    # produces the correct warning for the legacy tier, once opted in.
    test "warns about the legacy key tier when boot/1 runs and warn_on_boot is enabled" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.put_env(:phoenix_kit, :secret_key_base, "legacy-secret-for-boot-test")
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, true)

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      # Asserts the invariant, not the phrase. This line used to pin "no
      # dedicated key is configured", and stayed red for a whole round after
      # the wording moved into one source — the boot log renders
      # `Encryption.key_report/0` verbatim precisely so it has no wording of its
      # own to drift, and a test that pins a sentence re-creates the drift it
      # was meant to prevent. What must stay true is that the legacy tier is
      # named as the legacy tier.
      report = Encryption.key_report()

      assert report.diagnosis == {:legacy_secret_key_base, :no_dedicated_key}
      assert log =~ Encryption.key_report_message(report)
      refute log =~ "dedicated encryption key is in use"
    end

    # Plaintext states are reported on every boot unless the flag is an
    # explicit `false`.
    test "warns when no encryption key resolves and warn_on_boot is unset" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.delete_env(:phoenix_kit, :secret_key_base)
      original_parent = Application.get_env(:phoenix_kit, :parent_module)
      Application.put_env(:phoenix_kit, :parent_module, PhoenixKit.NoSuchApp)
      on_exit(fn -> restore_env(:parent_module, original_parent) end)

      assert Encryption.status() == :disabled_no_key

      Application.delete_env(:phoenix_kit, :integration_encryption_warn_on_boot)

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      assert log =~ Encryption.key_report_message(Encryption.key_report())
    end

    test "an explicit warn_on_boot: false silences the report when encryption is switched off" do
      original_enabled = Application.get_env(:phoenix_kit, :integration_encryption_enabled)
      on_exit(fn -> restore_env(:integration_encryption_enabled, original_enabled) end)
      Application.put_env(:phoenix_kit, :integration_encryption_enabled, false)
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, false)

      assert Encryption.status() == :disabled_explicit

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      refute log =~ Encryption.key_report_message(Encryption.key_report())
      refute log =~ "Failed to check integrations encryption status"
    end

    # Encryption is on but the key went missing: a fault, not a choice, so
    # the flag that quiets a deliberate switch-off must not hide it.
    test "an explicit warn_on_boot: false still reports that no encryption key resolves" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.delete_env(:phoenix_kit, :secret_key_base)
      original_parent = Application.get_env(:phoenix_kit, :parent_module)
      Application.put_env(:phoenix_kit, :parent_module, PhoenixKit.NoSuchApp)
      on_exit(fn -> restore_env(:parent_module, original_parent) end)
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, false)

      assert Encryption.status() == :disabled_no_key

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      assert log =~ Encryption.key_report_message(Encryption.key_report())
      refute log =~ "Failed to check integrations encryption status"
    end

    # A non-boolean config value (an unset `System.get_env/1` gives nil) must
    # not turn the boot check into a "Failed to check ..." error.
    test "still warns about plaintext storage when warn_on_boot is nil" do
      Application.delete_env(:phoenix_kit, :integrations_encryption_key)
      Application.delete_env(:phoenix_kit, :secret_key_base)
      original_parent = Application.get_env(:phoenix_kit, :parent_module)
      Application.put_env(:phoenix_kit, :parent_module, PhoenixKit.NoSuchApp)
      on_exit(fn -> restore_env(:parent_module, original_parent) end)
      Application.put_env(:phoenix_kit, :integration_encryption_warn_on_boot, nil)

      assert Encryption.status() == :disabled_no_key

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      assert log =~ Encryption.key_report_message(Encryption.key_report())
      refute log =~ "Failed to check integrations encryption status"
    end

    test "always warns when encryption is switched off explicitly, even with warn_on_boot unset" do
      original_enabled = Application.get_env(:phoenix_kit, :integration_encryption_enabled)
      Application.put_env(:phoenix_kit, :integration_encryption_enabled, false)
      Application.delete_env(:phoenix_kit, :integration_encryption_warn_on_boot)

      on_exit(fn -> restore_env(:integration_encryption_enabled, original_enabled) end)

      assert Encryption.status() == :disabled_explicit

      log = capture_log(fn -> PhoenixKit.boot({:ok, self()}) end)

      assert log =~ Encryption.key_report_message(Encryption.key_report())
    end

    test "PhoenixKit.Supervisor no longer runs this check itself" do
      {:ok, {_flags, children}} = PhoenixKit.Supervisor.init(nil)

      ids =
        Enum.map(children, fn
          %{id: id} -> id
          {mod, _arg} -> mod
          mod when is_atom(mod) -> mod
        end)

      refute :warn_integrations_encryption in ids
    end

    defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
    defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)
  end

  describe "boot/1 — :phoenix, :filter_parameters hardening" do
    setup do
      original = Application.get_env(:phoenix, :filter_parameters)
      on_exit(fn -> restore_phoenix_filter_parameters(original) end)
      :ok
    end

    test "sets password/token/secret/api_key when nothing was configured" do
      Application.delete_env(:phoenix, :filter_parameters)

      PhoenixKit.boot({:ok, self()})

      filter = Application.get_env(:phoenix, :filter_parameters)
      assert "password" in filter
      assert "secret" in filter
      assert "token" in filter
      assert "api_key" in filter
      assert "idempotency_key" in filter
    end

    # `aws_access_key_id` names neither half a keypair by convention — it
    # contains none of the generic words above — so it only gets caught by
    # being on `PhoenixKit.Settings.restricted_setting_keys/0`, the same
    # list the settings-display allow list is built from. Pins that this
    # function reads from there rather than carrying its own hand-kept
    # copy that could drift from it.
    test "also covers every PhoenixKit.Settings.restricted_setting_keys/0 entry" do
      Application.delete_env(:phoenix, :filter_parameters)

      PhoenixKit.boot({:ok, self()})

      filter = Application.get_env(:phoenix, :filter_parameters)

      for key <- PhoenixKit.Settings.restricted_setting_keys() do
        assert key in filter, "#{key} is restricted but not in :phoenix, :filter_parameters"
      end
    end

    # The API refuses these names in a URL with 400 token_in_url, but the request
    # line is logged at :debug first; the filter must cover every one of them.
    test "also covers every credential name the API refuses in a URL" do
      Application.delete_env(:phoenix, :filter_parameters)

      PhoenixKit.boot({:ok, self()})

      filter = Application.get_env(:phoenix, :filter_parameters)

      for name <- PhoenixKit.API.Auth.credential_params() do
        assert Enum.any?(filter, &String.contains?(name, &1)),
               "#{name} is refused in a URL but not covered by :phoenix, :filter_parameters"
      end
    end

    test "is idempotent — running boot/1 twice gives the same stable list" do
      Application.delete_env(:phoenix, :filter_parameters)

      PhoenixKit.boot({:ok, self()})
      first = Application.get_env(:phoenix, :filter_parameters)
      PhoenixKit.boot({:ok, self()})
      second = Application.get_env(:phoenix, :filter_parameters)

      assert first == second
      assert Enum.count(first, &(&1 == "secret")) == 1
    end

    test "leaves {:keep, [...]} mode untouched — unlisted keys are already filtered by default" do
      Application.put_env(:phoenix, :filter_parameters, {:keep, ["id", "order"]})

      PhoenixKit.boot({:ok, self()})

      assert Application.get_env(:phoenix, :filter_parameters) == {:keep, ["id", "order"]}
    end

    # Regression, found by a destructive test (a real LiveView save going
    # through the real code path — see
    # `PhoenixKitWeb.Live.Settings.AuthorizationSecretLeakTest`), not by
    # reasoning about the code: `Phoenix.start/2` — `:phoenix`'s own OTP app
    # boot, which always finishes before `boot/1` runs — pre-compiles
    # `:phoenix, :filter_parameters` into this opaque shape on EVERY boot,
    # not only when a host configured something themselves. Phoenix ships
    # its own package-level default env (`["password", "token"]`,
    # `deps/phoenix/mix.exs`), so this shape is not a rare case; it is what
    # `boot/1` ALWAYS sees in practice. A first version of this function
    # treated an already-compiled filter as "a host already configured
    # this, leave it alone" — which, given the above, meant "leave every
    # real host alone," protecting nobody. It must be replaced, not
    # skipped.
    test "replaces an already-compiled filter instead of leaving it alone (Phoenix.start/2 ran first)" do
      compiled = Phoenix.Logger.compile_filter(["password", "token"])
      Application.put_env(:phoenix, :filter_parameters, compiled)

      PhoenixKit.boot({:ok, self()})

      filter = Application.get_env(:phoenix, :filter_parameters)
      refute match?({:compiled, _, _}, filter)
      assert "secret" in filter
      assert "api_key" in filter
    end

    defp restore_phoenix_filter_parameters(nil),
      do: Application.delete_env(:phoenix, :filter_parameters)

    defp restore_phoenix_filter_parameters(value),
      do: Application.put_env(:phoenix, :filter_parameters, value)
  end

  describe "ScheduledJobs modules" do
    test "ScheduledJobs context is defined" do
      assert Code.ensure_loaded?(PhoenixKit.ScheduledJobs)
    end

    test "ScheduledJob schema is defined" do
      assert Code.ensure_loaded?(PhoenixKit.ScheduledJobs.ScheduledJob)
    end

    test "Handler behaviour is defined" do
      assert Code.ensure_loaded?(PhoenixKit.ScheduledJobs.Handler)
    end

    test "ProcessScheduledJobsWorker is defined" do
      assert Code.ensure_loaded?(PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker)
    end
  end
end
