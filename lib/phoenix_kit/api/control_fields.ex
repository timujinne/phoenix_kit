defmodule PhoenixKit.API.ControlFields do
  @moduledoc """
  The fields the executor adds to the input of a write tool: modules never declare them.
  `idempotency_key` is left out for a write tool that cannot replay (see below).

    * `dry_run` (boolean) - run the handler without side effects and return the
      preview; never creates a code or an approval.
    * `confirm_token` (string) - the one-time code of a dangerous operation, sent
      with the same arguments as the preview call.
    * `idempotency_key` (string, 16 to 128 characters of `[A-Za-z0-9_-]`) - makes a
      retry safe. REST clients may send it as the `Idempotency-Key` header instead.

  A read tool has none of them, so a request that sends one gets `422`, never a
  silent ignore. A write tool that cannot replay (`:replay` of `PhoenixKit.API.Tool`
  is `false`) has no `idempotency_key`; the `Idempotency-Key` header is ignored on it,
  as on a read tool.
  """

  alias PhoenixKit.API.Tool

  @names ["dry_run", "confirm_token", "idempotency_key"]

  @doc "The names of the control fields."
  @spec names() :: [String.t()]
  def names, do: @names

  @doc """
  Whether `tool` writes: its annotations do not say `read_only: true`. The only
  definition of "write tool" in the flow.
  """
  @spec write_tool?(Tool.t()) :: boolean()
  def write_tool?(%Tool{annotations: %{read_only: true}}), do: false
  def write_tool?(%Tool{}), do: true

  @doc """
  Whether `tool` takes an `idempotency_key`: a write tool that has not given up replay
  (`:replay` of `PhoenixKit.API.Tool`).
  """
  @spec replay_tool?(Tool.t()) :: boolean()
  def replay_tool?(%Tool{replay: false}), do: false
  def replay_tool?(%Tool{} = tool), do: write_tool?(tool)

  @doc "The JSON Schema properties the executor adds to `tool`'s input (`%{}` for a read tool)."
  @spec properties(Tool.t()) :: map()
  def properties(%Tool{} = tool) do
    if write_tool?(tool) do
      base = %{
        "dry_run" => %{
          "type" => "boolean",
          "description" =>
            "Run without side effects and return the preview. Never creates a confirmation code."
        },
        "confirm_token" => %{
          "type" => "string",
          "minLength" => 1,
          "maxLength" => 200,
          "description" =>
            "The one-time code returned with the preview of a dangerous operation. Send it with the same arguments."
        }
      }

      if replay_tool?(tool), do: Map.put(base, "idempotency_key", idempotency_key()), else: base
    else
      %{}
    end
  end

  defp idempotency_key do
    %{
      "type" => "string",
      "minLength" => 16,
      "maxLength" => 128,
      # `(?![\s\S])` means "nothing follows" in PCRE and in ECMA 262 alike, and the same
      # text is published to MCP and OpenAPI clients, where `\A` and `\z` do not exist.
      "pattern" => "^[A-Za-z0-9_-]{16,128}(?![\\s\\S])",
      "description" => "Makes a retry safe: the same key and arguments return the first answer."
    }
  end

  @doc "Splits a request body into the control fields and the tool's own input."
  @spec split(map()) :: {map(), map()}
  def split(input) when is_map(input), do: {Map.take(input, @names), Map.drop(input, @names)}
end
