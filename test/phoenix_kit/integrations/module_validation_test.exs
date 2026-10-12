defmodule PhoenixKit.Integrations.ModuleValidationTest do
  @moduledoc """
  A provider that another module contributes checks its connection through a
  module it names (`validation: %{strategy: :module, module: Mod}`), instead of
  falling through to "not verified".
  """
  # async: false — registers a fixture provider, which is global state.
  use PhoenixKit.DataCase, async: false

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

    def validate_connection(%{"api_key" => "echo"}),
      do: {:error, "locale: #{Gettext.get_locale(PhoenixKitWeb.Gettext)}"}
  end

  defmodule NoChecker do
    @moduledoc false
  end

  defmodule FixtureProvider do
    @moduledoc false
    def integration_providers do
      [
        provider("module_checked", Checker),
        provider("module_without_check", NoChecker),
        provider("module_not_loaded", Elixir.PhoenixKit.NoSuchModule)
      ]
    end

    defp provider(key, module) do
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
            required: true,
            placeholder: "",
            help: nil,
            options: nil
          }
        ],
        capabilities: [],
        scopes: [:system],
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

  defp connect(provider, key) do
    {:ok, %{uuid: uuid}} = Integrations.add_connection(provider, "test")
    {:ok, _} = Integrations.save_setup(uuid, %{"api_key" => key})
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
      assert {:error, message} = check("odd")
      assert message =~ "unexpected"
    end

    test "a module that raises does not take the caller down" do
      assert {:error, _message} = check("raises")
      assert Process.alive?(self())
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
  end

  describe "a provider whose module cannot check" do
    test "stays unverified when the module has no validate_connection/1" do
      uuid = connect("module_without_check", "good")
      assert Integrations.validate_connection(uuid) == :unverified
    end

    test "stays unverified when the module is not loaded" do
      uuid = connect("module_not_loaded", "good")
      assert Integrations.validate_connection(uuid) == :unverified
    end
  end

  describe "the credentials are still required first" do
    test "a connection with no key is not handed to the module" do
      {:ok, %{uuid: uuid}} = Integrations.add_connection("module_checked", "empty")
      assert {:error, _} = Integrations.validate_connection(uuid)
    end
  end
end
