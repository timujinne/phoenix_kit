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

  `validate_connection/1` gets the connection's data (the saved setup fields,
  string keys) once it is known to hold credentials, and answers like any other
  check: `:ok`, `{:ok, note}` (see `t:PhoenixKit.Integrations.Probe.note/0`),
  `:unverified` when it has no way to tell, or `{:error, message}` with
  something the operator can read. It runs through
  `PhoenixKit.Integrations.Probe`: in its own process, under a hard deadline,
  with `PhoenixKitWeb.Gettext` already in the operator's locale. A crash or an
  overrun comes back as an error; it does not reach the page.

  A module that is not loaded, or has no `validate_connection/1`, leaves the
  provider as it was: `:unverified`.
  """

  alias PhoenixKit.Integrations.Probe

  @doc "Checks the connection `data` against the service."
  @callback validate_connection(data :: map()) ::
              :ok | {:ok, Probe.note() | String.t()} | :unverified | {:error, String.t()}
end
