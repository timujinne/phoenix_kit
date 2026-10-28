defmodule PhoenixKit.Test.ApiFlowStore do
  @moduledoc """
  The in-memory data the `flowkit.*` test tools read and write: items by id, sessions, and
  a counter of real handler runs. `fingerprint/1` is the hash of the current values of
  some ids, which is exactly what a real tool's fingerprint is.
  """
  use Agent

  def start_link(_opts), do: Agent.start_link(fn -> %{items: %{}, calls: 0} end, name: __MODULE__)

  def reset(items), do: Agent.update(__MODULE__, fn _ -> %{items: Map.new(items), calls: 0} end)
  def items, do: Agent.get(__MODULE__, & &1.items)

  # The test process a `hold`ing handler reports to (see `ApiFlowTools.progress_write/2`).
  def set_gate(pid), do: Agent.update(__MODULE__, &Map.put(&1, :gate, pid))
  def gate, do: Agent.get(__MODULE__, &Map.get(&1, :gate))
  def put(id, value), do: Agent.update(__MODULE__, &put_in(&1, [:items, id], value))

  def delete(ids),
    do: Agent.update(__MODULE__, fn state -> %{state | items: Map.drop(state.items, ids)} end)

  def calls, do: Agent.get(__MODULE__, & &1.calls)

  def bump do
    Agent.get_and_update(__MODULE__, fn state ->
      calls = state.calls + 1
      {calls, %{state | calls: calls}}
    end)
  end

  def fingerprint(ids) do
    items = items()
    slice = ids |> Enum.sort() |> Enum.map(&{&1, Map.get(items, &1)})
    :crypto.hash(:sha256, :erlang.term_to_binary(slice)) |> Base.encode16(case: :lower)
  end
end

defmodule PhoenixKit.Test.ApiFlowTools do
  @moduledoc """
  A stand-in for a PhoenixKit module whose tools exercise the dangerous-operation flow.
  Register it with `PhoenixKit.Test.ApiFlowHarness.setup_flow/1`. Every handler sends `{:flow, tool, input, ctx}` to the
  process it runs in, and a dry run returns `{:preview, preview, fingerprint}` and writes
  nothing.
  """

  alias PhoenixKit.API.Tool
  alias PhoenixKit.Test.ApiFlowStore, as: Store

  @enabled_key {__MODULE__, :enabled}
  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}
  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}
  @destructive %{read_only: false, destructive: true, idempotent: false, open_world: false}

  @broken_dry_modes ~w(dry_bad_message dry_throw dry_exit dry_wrong_shape dry_tuple dry_struct dry_binary)

  @fingerprint_modes ~w(fingerprint_64 fingerprint_65 fingerprint_not_utf8)

  @danger_modes ~w(danger_raises danger_raises_input danger_key_error danger_throws danger_exits danger_dry_run danger_returns_yes danger_returns_nil)

  def module_key, do: "api_flow_tools"
  def module_name, do: "API flow test tools"
  def enabled?, do: :persistent_term.get(@enabled_key, true)
  def set_enabled(on?) when is_boolean(on?), do: :persistent_term.put(@enabled_key, on?)

  def api_problems do
    %{
      insufficient_stock: %{
        status: 422,
        title: "Insufficient stock",
        advice: "Reduce the quantities listed in context.lines; nothing was posted."
      }
    }
  end

  def api_tools do
    [
      admin("flowkit.read_items", "flowkit.items:read", "dashboard", @read, :read_items, %{}),
      admin("flowkit.read_many", "flowkit.items:read", "dashboard", @read, :read_many, %{
        "ids" => %{"type" => "array", "items" => %{"type" => "string"}}
      }),
      admin("flowkit.touch_item", "flowkit.items:write", "settings", @write, :touch_item, %{
        "name" => %{"type" => "string"}
      }),
      admin(
        "flowkit.batch_touch",
        "flowkit.items:write",
        "settings",
        @write,
        :batch_touch,
        %{"items" => %{"type" => "array", "items" => %{"type" => "object"}}},
        max_items: 500
      ),
      admin(
        "flowkit.set_values",
        "flowkit.items:write",
        "settings",
        @write,
        :set_values,
        %{
          "changes" => %{
            "type" => "array",
            "items" => %{
              "type" => "object",
              "required" => ["id", "value"],
              "properties" => %{"id" => %{"type" => "string"}, "value" => %{"type" => "number"}},
              "additionalProperties" => false
            }
          }
        },
        danger: {__MODULE__, :set_values_danger},
        title: "Change values"
      ),
      admin(
        "flowkit.delete_items",
        "flowkit.items:delete",
        "settings",
        @destructive,
        :delete_items,
        %{"ids" => %{"type" => "array", "minItems" => 1, "items" => %{"type" => "string"}}},
        danger: :always,
        max_items: 500,
        title: "Delete items"
      ),
      admin(
        "flowkit.progress_write",
        "flowkit.items:write",
        "settings",
        @write,
        :progress_write,
        %{
          "crash" => %{"type" => "boolean"},
          "credentials" => %{"type" => "boolean"},
          "fail" => %{"type" => "boolean"},
          "hold" => %{"type" => "boolean"}
        },
        danger: :always
      ),
      admin(
        "flowkit.misbehave",
        "flowkit.items:write",
        "settings",
        @write,
        :misbehave,
        %{
          "mode" => %{
            "type" => "string",
            "enum" =>
              ~w(ok write dry_error fail raise leak leak_link) ++
                @danger_modes ++ @broken_dry_modes ++ @fingerprint_modes
          },
          "note" => %{"type" => "string"}
        },
        danger: {__MODULE__, :misbehave_danger},
        credentials: ["link"]
      ),
      public("flowkit.mint_session", @write, :mint_session, %{}, replay: false),
      public(
        "flowkit.public_write",
        @write,
        :public_write,
        %{
          "text" => %{"type" => "string"},
          "session_token" => %{"type" => "string"},
          "lines" => %{"type" => "array", "items" => %{"type" => "object"}}
        },
        client_token: "session_token"
      ),
      public(
        "flowkit.clear_session",
        @destructive,
        :clear_session,
        %{"session_token" => %{"type" => "string"}},
        danger: :always,
        client_token: "session_token"
      ),
      # The no-replay twin of `flowkit.clear_session`.
      public(
        "flowkit.drop_session",
        @destructive,
        :clear_session,
        %{"session_token" => %{"type" => "string"}},
        danger: :always,
        client_token: "session_token",
        replay: false
      )
    ]
  end

  defp admin(name, scope, permission, annotations, function, properties, opts \\ []) do
    Tool.new!(
      name: name,
      audience: :admin,
      scope: scope,
      permission: permission,
      title: Keyword.get(opts, :title, name),
      description: "Test tool #{name}.",
      input_schema: %{
        "type" => "object",
        "properties" => properties,
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, function},
      annotations: annotations,
      danger: Keyword.get(opts, :danger),
      max_items: Keyword.get(opts, :max_items),
      credentials: Keyword.get(opts, :credentials, [])
    )
  end

  defp public(name, annotations, function, properties, opts) do
    Tool.new!(
      name: name,
      audience: :public,
      title: name,
      description: "Test tool #{name}.",
      input_schema: %{
        "type" => "object",
        "properties" => properties,
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, function},
      annotations: annotations,
      danger: Keyword.get(opts, :danger),
      replay: Keyword.get(opts, :replay, true),
      client_token: Keyword.get(opts, :client_token)
    )
  end

  # --- danger -----------------------------------------------------------------

  @doc "Dangerous when a value that is above 0 moves by more than 30 percent."
  def set_values_danger(%{"changes" => changes}, _ctx) do
    items = Store.items()

    Enum.any?(changes, fn %{"id" => id, "value" => value} ->
      case Map.get(items, id) do
        current when is_number(current) and current > 0 ->
          abs(value - current) / current * 100 > 30

        _first_value ->
          false
      end
    end)
  end

  # --- handlers ---------------------------------------------------------------

  def read_items(input, ctx) do
    send(self(), {:flow, "flowkit.read_items", input, ctx})
    {:ok, %{"items" => Store.items()}}
  end

  def read_many(input, ctx) do
    send(self(), {:flow, "flowkit.read_many", input, ctx})
    {:ok, %{"count" => length(Map.get(input, "ids", []))}}
  end

  def touch_item(input, ctx) do
    send(self(), {:flow, "flowkit.touch_item", input, ctx})
    name = Map.get(input, "name", "")

    if ctx.dry_run? do
      {:preview, %{"rows" => [%{"ref" => name, "action" => "touch"}]}, Store.fingerprint([name])}
    else
      {:ok, %{"touched" => name, "call" => Store.bump()}}
    end
  end

  def batch_touch(input, ctx) do
    send(self(), {:flow, "flowkit.batch_touch", input, ctx})
    count = length(Map.get(input, "items", []))

    if ctx.dry_run? do
      {:preview, %{"totals" => %{"touch" => count}}, Store.fingerprint(["batch"])}
    else
      Store.bump()
      {:ok, %{"count" => count}}
    end
  end

  def set_values(%{"changes" => changes} = input, ctx) do
    send(self(), {:flow, "flowkit.set_values", input, ctx})
    ids = Enum.map(changes, & &1["id"])

    if ctx.dry_run? do
      items = Store.items()

      rows =
        Enum.map(changes, fn %{"id" => id, "value" => value} ->
          %{
            "ref" => id,
            "changes" => %{"value" => %{"from" => Map.get(items, id), "to" => value}}
          }
        end)

      {:preview, %{"rows" => rows, "totals" => %{"update" => length(rows)}},
       Store.fingerprint(ids)}
    else
      Enum.each(changes, fn %{"id" => id, "value" => value} -> Store.put(id, value) end)
      {:ok, %{"updated" => length(changes)}, [%{"code" => "reindex_queued"}]}
    end
  end

  def delete_items(%{"ids" => ids} = input, ctx) do
    send(self(), {:flow, "flowkit.delete_items", input, ctx})

    if ctx.dry_run? do
      items = Store.items()
      rows = Enum.map(ids, &%{"ref" => &1, "action" => "delete", "from" => Map.get(items, &1)})

      {:preview, %{"rows" => rows, "totals" => %{"delete" => length(ids)}},
       Store.fingerprint(ids)}
    else
      Store.delete(ids)
      {:ok, %{"deleted" => length(ids)}}
    end
  end

  def progress_write(input, ctx) do
    send(self(), {:flow, "flowkit.progress_write", input, ctx})

    if ctx.dry_run? do
      {:preview, %{"totals" => %{"write" => 2}}, Store.fingerprint(["progress"])}
    else
      partial =
        if input["credentials"],
          do: %{"done" => 1, "rows" => [%{"Access_Token" => "private-progress-token"}]},
          else: %{"done" => 1}

      ctx.progress.(partial)
      if input["hold"], do: hold()
      if input["crash"], do: raise("boom with a secret-detail inside")

      if input["fail"],
        do: {:error, :insufficient_stock, "Two lines are short.", %{lines: []}},
        else: {:ok, %{"done" => 2}}
    end
  end

  # A real (not dry) run with `"hold" => true` tells the process set with `Store.set_gate/1`
  # which process it runs in, then waits (at most ten seconds) for `:release`. Without a
  # gate it does not wait. It is how a test kills the caller in the middle of an operation.
  defp hold do
    case Store.gate() do
      nil ->
        :ok

      owner ->
        send(owner, {:held, self()})

        receive do
          :release -> :ok
        after
          10_000 -> :ok
        end
    end
  end

  @doc """
  Dangerous only in the `danger_*` modes, where the check itself misbehaves and the gate
  must treat it as dangerous: it raises (`danger_raises`; `danger_raises_input` and
  `danger_key_error` with the request's `note` in the message), throws or exits with the
  `note`, or answers something that is not a boolean (`danger_returns_yes`,
  `danger_returns_nil`). `danger_dry_run` is a well-behaved check: dangerous exactly when
  the context it was called with says `dry_run?`.
  """
  def misbehave_danger(%{"mode" => "danger_raises"}, _ctx), do: raise("the danger check failed")

  def misbehave_danger(%{"mode" => "danger_raises_input", "note" => note}, _ctx),
    do: raise(ArgumentError, note)

  def misbehave_danger(%{"mode" => "danger_key_error", "note" => note}, _ctx),
    do: Map.fetch!(%{note => 1}, "missing")

  def misbehave_danger(%{"mode" => "danger_throws", "note" => note}, _ctx),
    do: throw({:note, note})

  def misbehave_danger(%{"mode" => "danger_exits", "note" => note}, _ctx),
    do: exit({:note, note})

  def misbehave_danger(%{"mode" => "danger_dry_run"}, ctx), do: ctx.dry_run? == true
  def misbehave_danger(%{"mode" => "danger_returns_yes"}, _ctx), do: :yes
  def misbehave_danger(%{"mode" => "danger_returns_nil"}, _ctx), do: nil
  def misbehave_danger(%{"mode" => mode}, _ctx) when mode in @fingerprint_modes, do: true
  def misbehave_danger(_input, _ctx), do: false

  @doc """
  Modes: `ok` (a normal tool); `write` (ignores the dry run and writes: a bug); `dry_error`
  (answers the dry run with an error); `fail` (the real run answers an error); `raise`
  (raises, dry run or not); `leak` (the real run answers a credential named `*_token`); `leak_link` (the real run
  answers a credential in the field `link`, which the tool declares in its `credentials`); `danger_raises`
  (a normal tool whose danger check raises). The `dry_*` modes break the dry-run contract in
  one way each, and only in a dry run (a real run is `ok`): `dry_bad_message` (an error whose
  message is not UTF-8), `dry_throw`, `dry_exit`, `dry_wrong_shape` (an `{:ok, map}`), and a
  preview JSON cannot hold: `dry_tuple`, `dry_struct`, `dry_binary`. Each carries the text
  `secret-detail`, which must never reach a log or an answer. The `fingerprint_*` modes are
  always dangerous and answer a dry run with a fingerprint of 64 characters (`fingerprint_64`,
  the longest the store holds), 65 (`fingerprint_65`) or one that is not UTF-8
  (`fingerprint_not_utf8`).
  """
  def misbehave(input, ctx) do
    send(self(), {:flow, "flowkit.misbehave", input, ctx})
    mode = Map.get(input, "mode", "ok")

    cond do
      mode == "write" ->
        {:ok, %{"wrote" => Store.bump()}}

      mode == "dry_error" and ctx.dry_run? ->
        {:error, :insufficient_stock, "Two lines are short.", %{lines: []}}

      mode == "raise" ->
        raise "boom with a secret-detail inside"

      ctx.dry_run? and mode in (@broken_dry_modes ++ @fingerprint_modes) ->
        broken_dry_run(mode)

      ctx.dry_run? ->
        {:preview, %{"totals" => %{"misbehave" => 1}}, Store.fingerprint(["misbehave"])}

      mode == "fail" ->
        {:error, :insufficient_stock, "Two lines are short.", %{lines: []}}

      mode == "leak" ->
        {:ok, %{"session_token" => "leaked-session-token-#{Store.bump()}"}}

      mode == "leak_link" ->
        {:ok, %{"link" => "https://example.test/open/#{Store.bump()}", "ok" => true}}

      true ->
        {:ok, %{"ok" => Store.bump()}}
    end
  end

  defp broken_dry_run("fingerprint_64"), do: fingerprinted(String.duplicate("f", 64))
  defp broken_dry_run("fingerprint_65"), do: fingerprinted(String.duplicate("f", 65))
  defp broken_dry_run("fingerprint_not_utf8"), do: fingerprinted(<<255>> <> "ffff")

  defp broken_dry_run("dry_bad_message"),
    do: {:error, :insufficient_stock, <<255>> <> "secret-detail", %{}}

  defp broken_dry_run("dry_throw"), do: throw({:secret_detail, "secret-detail"})
  defp broken_dry_run("dry_exit"), do: exit({:secret_detail, "secret-detail"})
  defp broken_dry_run("dry_wrong_shape"), do: {:ok, %{"note" => "secret-detail"}}

  defp broken_dry_run("dry_tuple"),
    do: {:preview, %{"rows" => [{:a, "secret-detail"}]}, Store.fingerprint(["misbehave"])}

  defp broken_dry_run("dry_struct"),
    do: {:preview, %{"rows" => [%URI{path: "secret-detail"}]}, Store.fingerprint(["misbehave"])}

  defp broken_dry_run("dry_binary"),
    do: {:preview, %{"note" => <<255>> <> "secret-detail"}, Store.fingerprint(["misbehave"])}

  defp fingerprinted(fingerprint),
    do: {:preview, %{"totals" => %{"misbehave" => 1}}, fingerprint}

  def mint_session(input, ctx) do
    send(self(), {:flow, "flowkit.mint_session", input, ctx})

    if ctx.dry_run?,
      do: {:preview, %{"totals" => %{"sessions" => 1}}, Store.fingerprint(["mint"])},
      else: {:ok, %{"session_token" => "secret-session-token-#{Store.bump()}"}}
  end

  def public_write(input, ctx) do
    send(self(), {:flow, "flowkit.public_write", input, ctx})

    if ctx.dry_run?,
      do: {:preview, %{"totals" => %{"writes" => 1}}, Store.fingerprint(["public"])},
      else: {:ok, %{"echo" => Map.get(input, "text"), "call" => Store.bump()}}
  end

  def clear_session(%{"session_token" => token} = input, ctx) do
    send(self(), {:flow, "flowkit.clear_session", input, ctx})
    ref = "session:" <> token

    if ctx.dry_run? do
      {:preview,
       %{
         "rows" => [%{"ref" => ref, "action" => "clear", "from" => Map.get(Store.items(), ref)}]
       }, Store.fingerprint([ref])}
    else
      Store.delete([ref])
      {:ok, %{"cleared" => true}}
    end
  end
end
