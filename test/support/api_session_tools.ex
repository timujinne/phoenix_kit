defmodule PhoenixKit.Test.ApiSessionTools do
  @moduledoc """
  A stand-in feature module for the tests of `PhoenixKit.API.Executor.execute_as/5`,
  `visible_for/3` and `redeem_as/6`: two **read** tools that declare the same scope but
  need different permissions (a session holds that scope only when its scope holds both),
  and two **write** tools over a small store of notes.

  | Tool | Scope | Permission | Danger |
  |---|---|---|---|
  | `sessiontest.read_a` | `sessiontest.shared:read` | `dashboard` | read |
  | `sessiontest.read_b` | `sessiontest.shared:read` | `users` | read |
  | `sessiontest.set_note` | `sessiontest.notes:write` | `settings` | none (`nil`) |
  | `sessiontest.wipe_note` | `sessiontest.notes:write` | `settings` | `:always` |

  The read handlers send `{:session_tool, name, ctx}` to the calling process. The write
  handlers answer a dry run with a preview in the common shape and the fingerprint of the
  note they touch, and write nothing then; a real run changes the note and sends
  `{:session_write, name, input, ctx}`. `reset_notes/1` sets the store, `put_note/2`
  changes a note behind the tool's back (the "data changed" case), `notes/0` reads it.
  """

  alias PhoenixKit.API.Tool

  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}
  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}
  @notes {__MODULE__, :notes}

  def module_key, do: "api_session_tools"
  def module_name, do: "API session test tools"
  def enabled?, do: true

  def scope, do: "sessiontest.shared:read"
  def write_scope, do: "sessiontest.notes:write"

  def api_tools do
    [
      tool(:read_a, "dashboard"),
      tool(:read_b, "users"),
      write_tool(:set_note, nil, %{"text" => %{"type" => "string"}}),
      write_tool(:wipe_note, :always, %{})
    ]
  end

  @doc "Sets the store of notes (id => text)."
  def reset_notes(notes \\ %{"n1" => "old"}), do: :persistent_term.put(@notes, notes)

  @doc "Changes a note without the tools: what another person's edit would do."
  def put_note(id, text), do: :persistent_term.put(@notes, Map.put(notes(), id, text))

  def notes, do: :persistent_term.get(@notes, %{})

  def read_a(_input, ctx), do: answer("sessiontest.read_a", ctx)
  def read_b(_input, ctx), do: answer("sessiontest.read_b", ctx)

  def set_note(%{"id" => id} = input, %{dry_run?: true}) do
    {:preview, preview(id, Map.get(notes(), id), input["text"]), fingerprint(id)}
  end

  def set_note(%{"id" => id} = input, ctx) do
    put_note(id, input["text"])
    send(self(), {:session_write, "sessiontest.set_note", input, ctx})
    {:ok, %{"id" => id, "updated" => true}}
  end

  def wipe_note(%{"id" => id}, %{dry_run?: true}),
    do: {:preview, preview(id, Map.get(notes(), id), nil), fingerprint(id)}

  def wipe_note(%{"id" => id} = input, ctx) do
    :persistent_term.put(@notes, Map.delete(notes(), id))
    send(self(), {:session_write, "sessiontest.wipe_note", input, ctx})
    {:ok, %{"id" => id, "deleted" => true}}
  end

  defp preview(id, from, to) do
    %{
      "rows" => [
        %{
          "ref" => id,
          "action" => "update",
          "changes" => %{"text" => %{"from" => from, "to" => to}}
        }
      ],
      "totals" => %{"rows" => 1, "update" => 1}
    }
  end

  defp fingerprint(id) do
    :crypto.hash(:sha256, :erlang.term_to_binary({id, Map.get(notes(), id)}))
    |> Base.encode16(case: :lower)
  end

  defp answer(name, ctx) do
    send(self(), {:session_tool, name, ctx})
    {:ok, %{"tool" => name}}
  end

  defp tool(verb, permission) do
    Tool.new!(
      name: "sessiontest.#{verb}",
      audience: :admin,
      scope: scope(),
      permission: permission,
      title: Atom.to_string(verb),
      description: "Test tool #{verb}.",
      input_schema: %{"type" => "object", "properties" => %{}, "additionalProperties" => false},
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, verb},
      annotations: @read
    )
  end

  defp write_tool(verb, danger, properties) do
    Tool.new!(
      name: "sessiontest.#{verb}",
      audience: :admin,
      scope: write_scope(),
      permission: "settings",
      title: Atom.to_string(verb),
      description: "Test tool #{verb}.",
      input_schema: %{
        "type" => "object",
        "properties" => Map.put(properties, "id", %{"type" => "string"}),
        "required" => ["id"],
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, verb},
      annotations: @write,
      danger: danger
    )
  end
end
