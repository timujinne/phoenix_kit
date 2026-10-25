defmodule PhoenixKit.Integrations.Validator do
  @moduledoc """
  A connection check supplied by the module that contributes a provider.

  The checks `PhoenixKit.Integrations` knows by name (`:smtp`, `:telegram`,
  `:aws_ses`, ...) belong to the providers PhoenixKit ships. A provider that
  comes from another module (`c:PhoenixKit.Module.integration_providers/0`)
  cannot add a clause there, and without one "Test Connection" can only answer
  "not verified". It names a module instead:

      %{
        key: "my_carrier",
        auth_type: :api_key,
        validation: %{strategy: :module, module: MyApp.Carrier},
        ...
      }

  and that module implements this behaviour:

      defmodule MyApp.Carrier do
        @behaviour PhoenixKit.Integrations.Validator

        @impl true
        def validate_connection(%{"api_key" => key}) do
          case MyApp.Carrier.Client.whoami(key) do
            {:ok, name} -> {:ok, %{fact: name}}
            {:error, :unauthorized} -> {:error, "The key was rejected"}
            {:error, _} -> {:error, "Could not reach the service"}
          end
        end
      end

  `validate_connection/1` (or `/2`, below) gets the connection's data (string
  keys: the setup fields, and for a saved connection what is stored beside
  them, such as `"status"`, so match on the keys you need and ignore the rest)
  once every required setup field of the provider is filled in, whether the
  connection is saved or the operator is testing it before saving; with a field
  missing the check is not run and "No credentials configured" is reported.
  Optional fields may still be absent, so a module that matches on one needs a
  clause for it being missing. The check answers like any other: `:ok`,
  `{:ok, note}` (see `t:PhoenixKit.Integrations.Probe.note/0`, `:fact` and
  `:reading` strings only), `:unverified` when it has no way to tell, or
  `{:error, message}` with something the operator can read
  (`{:inconclusive, message}` is reported as an error too). Any other answer is
  reported as an error.

  It runs through `PhoenixKit.Integrations.Probe`: in its own process, under a
  hard deadline, with `PhoenixKitWeb.Gettext` already in the operator's locale.
  A crash or an overrun comes back as an error; it does not reach the page. A
  crash is logged by its exception module only, because the arguments of a
  failed call are the credentials. Do the same for anything the module logs.

  Implement `validate_connection/2` to receive `owner:` in a keyword list:
  `:system` for a website-wide connection, or `{type, uuid}` for an owned one.
  Before saving, this comes from the caller's `:owner` option; for a saved
  connection it comes from the stored row, even with an owner-agnostic read.
  If both callbacks are exported, `/2` takes precedence. Implement at least one.

  A check that dials an operator-supplied host must use `/2` and apply the
  appropriate endpoint policy (for example `PhoenixKit.Modules.Storage.Endpoint`
  with `:personal` for any typed owner). The `/1` callback remains supported for
  checks against fixed service endpoints. Owner context does not itself enforce
  an endpoint policy; the module must check before connecting, including on its
  normal service requests.

  A module that is not loaded, or exports neither callback, leaves the
  provider as it was: `:unverified`. So does a provider whose `validation` names
  no `module:`.
  """

  alias PhoenixKit.Integrations.Probe

  @type verdict ::
          :ok
          | {:ok, Probe.note() | String.t()}
          | :unverified
          | {:error, String.t()}
          | {:inconclusive, String.t()}

  @doc "Checks the connection `data` against the service."
  @callback validate_connection(data :: map()) :: verdict()

  @doc "Checks the connection with trusted owner context for endpoint policy decisions."
  @callback validate_connection(data :: map(), opts :: [owner: PhoenixKit.Integrations.owner()]) ::
              verdict()

  @optional_callbacks validate_connection: 1, validate_connection: 2
end
