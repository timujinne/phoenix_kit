defmodule PhoenixKit.Integrations.ModuleValidationTest do
  @moduledoc """
  A provider that another module contributes checks its connection through a
  module it names (`validation: %{strategy: :module, module: Mod}`), instead of
  falling through to "not verified".
  """
  # async: false — registers a fixture provider, which is global state.
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Providers
  alias PhoenixKit.ModuleRegistry

  # The module that does the check. What it answers depends on the key it is
  # given, so one fixture covers every verdict.
  defmodule Checker do
    @moduledoc false
    @behaviour PhoenixKit.Integrations.Validator

    @impl true
    def validate_connection(%{"api_key" => "good"}), do: :ok
    def validate_connection(%{"api_key" => "named"}), do: {:ok, %{fact: "Account Acme"}}
    def validate_connection(%{"api_key" => "plain"}), do: {:ok, "Account Plain"}
    def validate_connection(%{"api_key" => "unsure"}), do: :unverified
    def validate_connection(%{"api_key" => "unclear"}), do: {:inconclusive, "No yes or no"}
    def validate_connection(%{"api_key" => "bad"}), do: {:error, "The key was rejected"}
    def validate_connection(%{"api_key" => "odd"}), do: :perhaps
    def validate_connection(%{"api_key" => "raises"}), do: raise("boom")
    def validate_connection(%{"api_key" => "throws"}), do: throw(:boom)
    def validate_connection(%{"api_key" => "exits"}), do: exit(:boom)
    def validate_connection(%{"api_key" => "string_keys"}), do: {:ok, %{"fact" => "Account Acme"}}
    def validate_connection(%{"api_key" => "struct_note"}), do: {:ok, %URI{path: "x"}}
    def validate_connection(%{"api_key" => "hangs"}), do: Process.sleep(:infinity)
    def validate_connection(%{"api_key" => "empty_ok"}), do: {:ok, ""}
    def validate_connection(%{"api_key" => "empty_note"}), do: {:ok, %{}}
    def validate_connection(%{"api_key" => "bad_note"}), do: {:ok, %{fact: {:not, :text}}}

    def validate_connection(%{"api_key" => "leaks"}),
      do: {:error, %{api_key: "SECRET-ANSWER-456"}}

    def validate_connection(%{"api_key" => "echo"}),
      do: {:error, "locale: #{Gettext.get_locale(PhoenixKitWeb.Gettext)}"}
  end

  # No catch-all clause, as the `Validator` moduledoc's own example: a map
  # without the key it matches crashes with a `FunctionClauseError`.
  defmodule Strict do
    @moduledoc false
    @behaviour PhoenixKit.Integrations.Validator

    @impl true
    def validate_connection(%{"api_key" => key}) when is_binary(key), do: :ok
  end

  defmodule OwnerChecker do
    @moduledoc false
    @behaviour PhoenixKit.Integrations.Validator

    @impl true
    def validate_connection(%{"api_key" => "owner"}, owner: owner),
      do: {:ok, %{fact: inspect(owner), reading: inspect(owner)}}

    def validate_connection(%{"api_key" => "raise:" <> secret}, _opts), do: raise(secret)
    def validate_connection(%{"api_key" => "throw:" <> secret}, _opts), do: throw(secret)
    def validate_connection(%{"api_key" => "exit:" <> secret}, _opts), do: exit(secret)
    def validate_connection(data, _opts), do: Checker.validate_connection(data)
  end

  defmodule BothCheckers do
    @moduledoc false
    @behaviour PhoenixKit.Integrations.Validator

    @impl true
    def validate_connection(_data), do: {:error, "The legacy callback must not run"}

    @impl true
    def validate_connection(data, opts), do: OwnerChecker.validate_connection(data, opts)
  end

  defmodule NoChecker do
    @moduledoc false
  end

  defmodule FixtureProvider do
    @moduledoc false
    def integration_providers do
      [
        provider("module_checked", Checker),
        provider("module_owner", OwnerChecker),
        provider("module_both", BothCheckers),
        provider("module_numeric", Checker)
        |> Map.put(:auth_type, :credentials)
        |> Map.update!(:setup_fields, fn fields ->
          fields ++ [%{key: "port", type: :number, required: true}]
        end),
        provider("module_without_check", NoChecker),
        provider("module_not_loaded", Elixir.PhoenixKit.NoSuchModule),
        provider("module_strict", Strict, false),
        provider("module_not_an_atom", "Elixir.PhoenixKit.NoSuchModule"),
        Map.put(provider("module_unnamed", nil), :validation, %{strategy: :module})
      ]
    end

    defp provider(key, module, required \\ true) do
      %{
        key: key,
        name: "Fixture #{key}",
        description: "Test-only provider with a module check",
        icon: "hero-beaker",
        auth_type: :api_key,
        oauth_config: nil,
        setup_fields: [
          %{
            key: "api_key",
            label: "API key",
            type: :password,
            required: required,
            placeholder: "",
            help: nil,
            options: nil
          }
        ],
        capabilities: [],
        scopes: [:system, :personal],
        validation: %{strategy: :module, module: module}
      }
    end
  end

  setup do
    ModuleRegistry.register(FixtureProvider)
    Providers.clear_cache()

    on_exit(fn ->
      ModuleRegistry.unregister(FixtureProvider)
      Providers.clear_cache()
    end)

    :ok
  end

  defp connect(provider, key, opts \\ []) do
    {:ok, %{uuid: uuid}} = Integrations.add_connection(provider, "test", nil, opts)
    {:ok, _} = Integrations.save_setup(uuid, %{"api_key" => key}, nil, opts)
    uuid
  end

  defp check(key), do: "module_checked" |> connect(key) |> Integrations.validate_connection()

  describe "validate_connection/3 with a module check" do
    test "a pass is :ok" do
      assert check("good") == :ok
    end

    test "a pass with a fact keeps the note" do
      assert check("named") == {:ok, %{fact: "Account Acme"}}
      assert check("plain") == {:ok, "Account Plain"}
    end

    test "a rejection carries the module's message" do
      assert check("bad") == {:error, "The key was rejected"}
    end

    test "a module with no way to tell leaves the connection unverified" do
      assert check("unsure") == :unverified
    end

    test "an inconclusive check is reported with its message, not as a pass" do
      assert check("unclear") == {:error, "No yes or no"}
    end

    test "an answer outside the contract is an error, not a guess" do
      log =
        capture_log(fn ->
          assert {:error, message} = check("odd")
          assert message =~ "unexpected"
        end)

      assert log =~ "answered an atom"
    end

    test "a module that raises does not take the caller down" do
      log =
        capture_log(fn ->
          assert check("raises") == {:error, "Validation failed unexpectedly"}
          assert check("throws") == {:error, "Validation failed unexpectedly"}
          assert check("exits") == {:error, "Validation failed unexpectedly"}
        end)

      assert log =~ "#{inspect(Checker)}.validate_connection/1 failed with ** (RuntimeError)"
      assert log =~ "failed with an uncaught throw"
      assert log =~ "failed with an uncaught exit"
    end

    test "a module that never answers is cut off at the deadline" do
      Application.put_env(:phoenix_kit, :integration_check_deadline, 50)
      on_exit(fn -> Application.delete_env(:phoenix_kit, :integration_check_deadline) end)

      capture_log(fn -> assert {:error, _message} = check("hangs") end)
    end

    test "a crash does not write the credentials it was handed to the log" do
      sentinel = "SECRET-#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          # The key is optional here, so the module meets a map without it — the
          # case the moduledoc's own example crashes on.
          assert {:error, _} =
                   Integrations.validate_credentials("module_strict", %{"other" => sentinel})
        end)

      assert log =~ "FunctionClauseError"
      refute log =~ sentinel
    end

    test "an answer outside the contract is not written to the log" do
      log = capture_log(fn -> assert {:error, _} = check("leaks") end)

      assert log =~ "answered a tuple of size 2 tagged :error"
      refute log =~ "SECRET-ANSWER-456"
    end

    test "an empty note is a plain pass" do
      assert check("empty_ok") == :ok
      assert check("empty_note") == {:ok, %{}}
    end

    test "a note that is not a plain map of text under :fact and :reading is an unexpected answer" do
      capture_log(fn ->
        for key <- ["bad_note", "string_keys", "struct_note"] do
          assert {:error, message} = check(key)
          assert message =~ "unexpected"
        end
      end)
    end

    test "the check runs in the operator's locale" do
      Gettext.put_locale(PhoenixKitWeb.Gettext, "uk")
      assert check("echo") == {:error, "locale: uk"}
    end

    test "its verdict is recorded on the connection like any other" do
      uuid = connect("module_checked", "named")
      Integrations.record_validation(uuid, Integrations.validate_connection(uuid))

      {:ok, %{data: data}} = Integrations.get_integration_by_uuid(uuid, :system)
      assert data["status"] == "connected"
      assert data["validation_status"] == "Account Acme"

      uuid = connect("module_checked", "bad")
      Integrations.record_validation(uuid, Integrations.validate_connection(uuid))

      {:ok, %{data: data}} = Integrations.get_integration_by_uuid(uuid, :system)
      assert data["status"] == "error"
      assert data["validation_status"] =~ "The key was rejected"
    end
  end

  describe "validate_credentials/3 (before saving)" do
    test "asks the module too" do
      assert Integrations.validate_credentials("module_checked", %{"api_key" => "good"}) == :ok

      assert Integrations.validate_credentials("module_checked", %{"api_key" => "bad"}) ==
               {:error, "The key was rejected"}
    end

    test "required number fields accept numeric values before and after saving" do
      for port <- [0, 587, 587.0, "587"] do
        attrs = %{"api_key" => "good", "port" => port}
        assert Integrations.validate_credentials("module_numeric", attrs) == :ok

        {:ok, %{uuid: uuid}} =
          Integrations.add_connection(
            "module_numeric",
            "port-#{System.unique_integer([:positive])}"
          )

        {:ok, _} = Integrations.save_setup(uuid, attrs)
        assert Integrations.validate_connection(uuid) == :ok
      end
    end

    test "a missing or blank required number field never reaches the module" do
      for attrs <- [
            %{"api_key" => "good"},
            %{"api_key" => "good", "port" => nil},
            %{"api_key" => "good", "port" => ""}
          ] do
        assert Integrations.validate_credentials("module_numeric", attrs) ==
                 {:error, "No credentials configured"}
      end
    end

    test "does not hand the module a form with a required field empty" do
      expected = {:error, "No credentials configured"}

      assert Integrations.validate_credentials("module_checked", %{}) == expected
      assert Integrations.validate_credentials("module_checked", %{"api_key" => ""}) == expected
    end
  end

  describe "owner-aware module checks" do
    test "pre-save checks receive the caller's owner, ignoring forged owner fields" do
      attrs = %{"api_key" => "owner", "owner_uuid" => UUIDv7.generate(), "owner_type" => "user"}
      assert {:ok, %{fact: ":system"}} = Integrations.validate_credentials("module_owner", attrs)

      for type <- [:user, :dashboard] do
        owner = {type, UUIDv7.generate()}
        expected = inspect(owner)

        assert {:ok, %{fact: ^expected}} =
                 Integrations.validate_credentials("module_owner", attrs, owner: owner)
      end
    end

    test "saved checks and readings receive the row owner, including owner-agnostic calls" do
      for owner <- [:system, {:user, UUIDv7.generate()}, {:dashboard, UUIDv7.generate()}] do
        uuid = connect("module_owner", "owner", owner: owner)
        expected = inspect(owner)

        for requested_owner <- [owner, :any] do
          assert {:ok, %{fact: ^expected}} =
                   Integrations.validate_connection(uuid, nil, owner: requested_owner)

          assert Integrations.reading(uuid, owner: requested_owner) == {:ok, expected}
        end
      end
    end

    test "a mismatched owner cannot reach the check through validation or reading" do
      uuid = connect("module_owner", "owner", owner: {:user, UUIDv7.generate()})

      for owner <- [:system, {:user, UUIDv7.generate()}] do
        assert {:error, "Not configured"} =
                 Integrations.validate_connection(uuid, nil, owner: owner)

        assert Integrations.reading(uuid, owner: owner) == {:error, "Not configured"}
      end
    end

    test "the owner-aware callback takes precedence when both callbacks exist" do
      assert {:ok, %{fact: ":system"}} =
               Integrations.validate_credentials("module_both", %{"api_key" => "owner"})
    end

    test "owner-aware checks retain crash isolation, redaction and locale" do
      sentinel = "SECRET-#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          for prefix <- ["raise:", "throw:", "exit:"] do
            assert {:error, "Validation failed unexpectedly"} =
                     Integrations.validate_credentials("module_owner", %{
                       "api_key" => prefix <> sentinel
                     })
          end
        end)

      assert log =~ "#{inspect(OwnerChecker)}.validate_connection/2 failed"
      refute log =~ sentinel
      Gettext.put_locale(PhoenixKitWeb.Gettext, "uk")

      assert Integrations.validate_credentials("module_owner", %{"api_key" => "echo"}) ==
               {:error, "locale: uk"}
    end

    test "owner-aware checks still require credentials and obey the deadline" do
      assert {:error, "No credentials configured"} =
               Integrations.validate_credentials("module_owner", %{})

      previous = Application.get_env(:phoenix_kit, :integration_check_deadline)
      Application.put_env(:phoenix_kit, :integration_check_deadline, 50)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:phoenix_kit, :integration_check_deadline, previous),
          else: Application.delete_env(:phoenix_kit, :integration_check_deadline)
      end)

      assert {:error, "The service did not respond in time"} =
               Integrations.validate_credentials("module_owner", %{"api_key" => "hangs"})
    end
  end

  describe "a provider whose module cannot check" do
    test "stays unverified when the module has no validate_connection/1" do
      capture_log(fn ->
        uuid = connect("module_without_check", "good")
        assert Integrations.validate_connection(uuid) == :unverified
      end)
    end

    test "stays unverified when the module is not loaded" do
      log =
        capture_log(fn ->
          uuid = connect("module_not_loaded", "good")
          assert Integrations.validate_connection(uuid) == :unverified
        end)

      assert log =~ "has no validate_connection/1"
    end

    test "stays unverified when the provider names no module, or not an atom" do
      capture_log(fn ->
        for key <- ["module_unnamed", "module_not_an_atom"] do
          assert Integrations.validate_credentials(key, %{"api_key" => "good"}) == :unverified
          assert key |> connect("good") |> Integrations.validate_connection() == :unverified
        end
      end)
    end
  end

  describe "the credentials are still required first" do
    test "a connected status cannot replace a missing required field" do
      uuid = connect("module_checked", "good")
      assert :ok = Integrations.record_validation(uuid, :ok)
      {:ok, _} = Integrations.save_setup(uuid, %{"api_key" => ""})
      {:ok, %{data: data}} = Integrations.get_integration_by_uuid(uuid)
      assert data["status"] == "connected"
      assert Integrations.validate_connection(uuid) == {:error, "No credentials configured"}
    end

    test "a connection with no key is not handed to the module" do
      {:ok, %{uuid: uuid}} = Integrations.add_connection("module_checked", "empty")
      assert {:error, _} = Integrations.validate_connection(uuid)
    end
  end
end
