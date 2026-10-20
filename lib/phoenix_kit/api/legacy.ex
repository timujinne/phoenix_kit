defmodule PhoenixKit.API.Legacy do
  @moduledoc """
  Every name the machine API had before it was made module-neutral, in one
  place. The rest of `PhoenixKit.API` knows no module (a guard test fails when
  it spells one), so the day the deprecation window closes this file is
  deleted and only its callers are touched: `PhoenixKit.API.Paths`, the
  fallback in `PhoenixKit.API.Config.rate_limits/0` (with
  `rate_limits_without_fallback/0`, which exists only for it), the
  Settings -> API form's `write_limits`, `PhoenixKit.API.Problem` (the four
  error codes of the shop), `PhoenixKit.API.Executor` (the client token of a tool that
  declares none) and `PhoenixKit.API.Idempotency` (the
  credential names and markers of the old checkout links).

  **This module is deleted in 3.0.0.** A client, a settings row or a module
  that still uses a name below has until then to move to the canonical one.

  What it holds:

    * the deprecated public paths, `/api/shop/v1` and `/mcp/shop`
      (`alias_paths/0`): `PhoenixKit.API.Paths` forwards them to the same
      plugs as the canonical `/api/public/v1` and `/mcp/public`, and the
      plugs mark every answer with `deprecation/0` and a `Link` to the
      canonical path;
    * the deprecated settings keys (`setting_fallback/1`): `PhoenixKit.API.Config`
      reads a limit from its new key and, when that holds no valid number, from
      the old one. Nothing deletes or migrates the old rows; the first save of
      Settings -> API writes the values in effect under the new keys;
    * the client token of a public tool that declares none (`legacy_client_token/1`):
      a module written before `PhoenixKit.API.Tool` had a `client_token` field named
      its anonymous caller's token `cart_token`, and the executor still reads it so
      such a module keeps its rate limit, its idempotency scope and its danger gate;
    * the four error codes the shop API answered with before modules could declare
      their own (`problems/0`): `PhoenixKit.API.Problem` (and, through it, the MCP advice)
      uses them for as long as no enabled module declares the same code
      (`c:PhoenixKit.Module.api_problems/0`);
    * the names a module's answers carried secrets under before `Tool.credentials`
      existed (`credential_keys/0`, `credential_markers/0`), which
      `PhoenixKit.API.Idempotency` still redacts and never stores for replay.
  """

  # 2026-10-20T00:00:00Z, the day the neutral paths shipped, as an RFC 9745
  # `Deprecation` date (`@` and Unix seconds).
  @deprecation "@1792454400"

  # The public REST and MCP paths, as segments under the kit's URL prefix.
  @alias_paths [["api", "shop", "v1"], ["mcp", "shop"]]

  # New settings key => the key it replaces.
  @setting_fallbacks %{
    "api_public_token_rate_per_min" => "api_public_cart_rate_per_min",
    "api_public_new_rows_per_ip_hour" => "api_public_cart_rows_per_ip_hour",
    "api_public_new_rows_global_hour" => "api_public_cart_rows_global_hour"
  }

  # Output field names that carried a secret without ending in `_token`, and the part of
  # a checkout link that holds the secret. `claim_token` is also caught by the `_token`
  # rule of core; it is listed because it was named.
  @credential_keys ~w(claim_url checkout_url claim_token)
  @credential_markers ["/checkout/claim/"]

  # The wire values (`code`, `status`, `title`) are a contract with clients and must not
  # change; the advice is what MCP tells an agent after the error.
  @problems %{
    cart_not_found: %{
      status: 404,
      title: "Cart not found",
      advice: "Create a new cart and try again."
    },
    cart_locked: %{
      status: 409,
      title: "Cart locked",
      advice: "The cart is already in checkout; start a new cart."
    },
    unsupported_source: %{
      status: 422,
      title: "Unsupported source",
      advice: "This product source cannot be changed through the API."
    },
    insufficient_stock: %{
      status: 422,
      title: "Insufficient stock",
      advice: "Reduce the quantities listed in context.lines; nothing was posted."
    }
  }

  @doc """
  The value of the `Deprecation` response header (RFC 9745) that every answer
  on a deprecated path carries.
  """
  @spec deprecation() :: String.t()
  def deprecation, do: @deprecation

  @doc """
  The deprecated public API paths, as lists of segments (the REST one, then the
  MCP one). Each is served by the plug of the canonical public path of its
  transport, and nothing publishes them: documents and headers name the
  canonical path only.
  """
  @spec alias_paths() :: [[String.t()]]
  def alias_paths, do: @alias_paths

  @doc """
  The deprecated settings key that `key` replaces, or `nil` when `key` replaced
  none. `PhoenixKit.API.Config.int/3` reads it when `key` holds no valid number.
  """
  @spec setting_fallback(String.t()) :: String.t() | nil
  def setting_fallback(key) when is_binary(key), do: Map.get(@setting_fallbacks, key)

  @doc """
  The input field a public `tool` that declares no `client_token` is read through, or
  `nil`: `"cart_token"` when the tool's input schema has a property of that name.
  """
  @spec legacy_client_token(PhoenixKit.API.Tool.t()) :: String.t() | nil
  def legacy_client_token(%PhoenixKit.API.Tool{audience: :public, client_token: nil} = tool) do
    if has_cart_token_property?(tool.input_schema), do: "cart_token"
  end

  def legacy_client_token(%PhoenixKit.API.Tool{}), do: nil

  # `Tool.new/1` accepts a schema keyed by strings or by atoms.
  defp has_cart_token_property?(%{} = schema) do
    case Map.get(schema, "properties", Map.get(schema, :properties)) do
      %{} = properties ->
        Map.has_key?(properties, "cart_token") or Map.has_key?(properties, :cart_token)

      _no_properties ->
        false
    end
  end

  defp has_cart_token_property?(_schema), do: false

  @doc """
  The output field names `PhoenixKit.API.Idempotency` treats as credentials besides the
  ones core's rule covers.
  """
  @spec credential_keys() :: [String.t()]
  def credential_keys, do: @credential_keys

  @doc """
  The substrings that make any string value of an answer a credential
  (compared without regard to case).
  """
  @spec credential_markers() :: [String.t()]
  def credential_markers, do: @credential_markers

  @doc """
  The error codes the shop answered with before modules declared their own, as
  `%{code => %{status, title, advice}}`. They apply to a code only while no enabled
  module declares it.
  """
  @spec problems() :: %{
          atom() => %{status: pos_integer(), title: String.t(), advice: String.t()}
        }
  def problems, do: @problems
end
