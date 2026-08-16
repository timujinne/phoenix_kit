defmodule PhoenixKit do
  @moduledoc """
  PhoenixKit
  """

  alias PhoenixKit.Config
  alias PhoenixKit.Users.Permissions

  @doc """
  Returns the current version of PhoenixKit.

  Read from the loaded application spec, so it always reports the version the
  host actually has rather than anything written down here — the example this
  replaced still claimed `"1.3.3"` several majors later.

      PhoenixKit.version()
      #=> "2.5.0"

  """
  @spec version() :: String.t()
  def version do
    Application.spec(:phoenix_kit, :vsn) |> to_string()
  end

  @doc """
  Validates if PhoenixKit is properly configured.

  Checks for required configuration keys and returns a status.

  ## Examples

      iex> PhoenixKit.configured?()
      false

  """
  @spec configured?() :: boolean()
  def configured? do
    case Config.get(:repo, nil) do
      nil -> false
      _repo -> true
    end
  end

  @doc """
  Returns PhoenixKit configuration.

  ## Examples

      iex> PhoenixKit.config()
      %{ecto_repos: []}

  """
  @spec config() :: map()
  def config do
    :phoenix_kit
    |> Application.get_all_env()
    |> Enum.into(%{})
  end

  @doc """
  Final boot step — call from `Application.start/2` right after
  `Supervisor.start_link/2`.

  Picks up `:phoenix_kit_<x>` modules whose beams loaded after
  `PhoenixKit.ModuleRegistry` initialised (a `:phoenix_kit_*` dep starts
  *after* `:phoenix_kit` itself, so the registry's first scan can miss
  it), then runs every registered module's `migrate_legacy/0` callback.

  Returns the supervisor result unchanged so it composes:

      def start(_type, _args) do
        children = [...]
        opts = [strategy: :one_for_one, name: MyApp.Supervisor]
        Supervisor.start_link(children, opts) |> PhoenixKit.boot()
      end

  If `Supervisor.start_link/2` returned `{:error, _}`, this is a no-op —
  the error passes through unchanged.

  `mix phoenix_kit.install` and `mix phoenix_kit.update` wire this in
  automatically; existing apps can add the call manually.
  """
  @spec boot({:ok, pid()} | {:error, term()}) :: {:ok, pid()} | {:error, term()}
  def boot({:ok, _pid} = result) do
    PhoenixKit.ModuleRegistry.rescan()
    PhoenixKit.ModuleRegistry.run_all_legacy_migrations()
    register_custom_permission_keys()
    result
  end

  def boot({:error, _reason} = result), do: result

  # Custom permission keys declared in config:
  #
  #     config :phoenix_kit,
  #       custom_permission_keys: [
  #         {"analytics", label: "Analytics"},
  #         "exports"
  #       ]
  #
  # `Permissions.register_custom_key/2` has to run AFTER boot, because the Admin
  # auto-grant touches the database — which is why it could not simply be read
  # from config at compile time, and why every host was writing an imperative
  # call at the end of its own `Application.start/2`. Admin *tabs* have been
  # declarative all along; permission keys were the odd one out.
  #
  # ⚠️ Two things a host needs to know:
  #
  #   * This is only read from `boot/1`, which is opt-in. A host that never calls
  #     it registers nothing, silently. `install`/`update` wire the call in.
  #   * It is read once, at boot. Changing the config needs a restart.
  #
  # A key that already has an admin tab carrying `permission:` is registered by
  # that tab and must NOT be listed here — double-registration hits the override
  # path. This is for matrix-only keys with no tab of their own.
  #
  # Bad entries RAISE, failing app start. Config is a deploy-time contract, and
  # logging-and-skipping would hide the mistake until a colleague hit a 403 —
  # exactly the failure declaring keys is meant to prevent. (`Dashboard.Registry`
  # rescues instead, correctly: one bad tab should not take the dashboard down.)
  defp register_custom_permission_keys do
    :phoenix_kit
    |> Application.get_env(:custom_permission_keys, [])
    |> Enum.each(fn
      {key, opts} when is_binary(key) and is_list(opts) ->
        Permissions.register_custom_key(key, opts)

      key when is_binary(key) ->
        Permissions.register_custom_key(key)

      other ->
        raise ArgumentError, """
        Invalid entry in config :phoenix_kit, :custom_permission_keys — #{inspect(other)}

        Each entry must be a key string, or a {key, opts} tuple:

            custom_permission_keys: [
              "exports",
              {"analytics", label: "Analytics"}
            ]
        """
    end)
  end
end
