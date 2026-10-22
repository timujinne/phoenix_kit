defmodule PhoenixKitWeb.Components.Core.OperationPreview do
  @moduledoc """
  What an API operation that waits for a person would change: the preview a write tool
  answered with, read from the shape every module's tools share
  (`PhoenixKit.API.Approvals.View`) into the totals as a sentence, the warnings, a table of
  item, field, was, becomes and the change in percent, and whatever does not fit that shape,
  whole, under "Technical details".

  `operation_preview/1` is for a page that shows such an operation outside the approvals
  queue, for instance a confirmation of a person's live session read with
  `PhoenixKit.API.Confirm.get_for_user/2`:

      <.operation_preview id={"confirmation-" <> confirmation.uuid} preview={confirmation.preview} />

  It draws only the preview; the frame, the title and the buttons belong to the page. Every
  value is shown as text, never as markup or a link. The approvals page
  (`PhoenixKitWeb.Live.Approvals`) keeps its own layout and uses the row and text helpers of
  this module.

  Opt-in (not in the global import list): `import
  PhoenixKitWeb.Components.Core.OperationPreview, only: [operation_preview: 1]`.
  """
  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.Icon

  alias PhoenixKit.API.Approvals.View

  @doc """
  The preview of one operation. `id` prefixes the ids inside it (`<id>-totals`, `<id>-rows`,
  `<id>-row-<n>`, `<id>-truncated`, `<id>-technical`); `preview` is the map the tool
  answered its dry run with; `tool`, when given, is named under "Technical details".
  """
  attr :id, :string, required: true
  attr :preview, :map, required: true, doc: "the preview as the tool answered it"
  attr :tool, :string, default: nil, doc: "the tool's name, shown with the technical details"
  attr :class, :any, default: nil

  def operation_preview(assigns) do
    assigns = assign(assigns, :view, View.preview(assigns.preview))

    ~H"""
    <div id={@id} class={["space-y-2", @class]}>
      <div class="text-sm font-medium">{gettext("What would change")}</div>

      <p :if={@view.summary != []} id={@id <> "-totals"} class="text-sm">
        {gettext("Summary: %{summary}.", summary: sentence(@view.summary))}
      </p>

      <div :for={warning <- @view.warnings} class="flex items-start gap-2 text-sm text-warning">
        <.icon name="hero-exclamation-triangle" class="w-4 h-4 mt-0.5 shrink-0" />
        <span>{warning}</span>
      </div>

      <div :if={@view.rows != []} class="max-h-96 overflow-auto rounded border border-base-200">
        <table id={@id <> "-rows"} class="table table-sm table-pin-rows">
          <thead>
            <tr>
              <th>{gettext("Item")}</th>
              <th>{gettext("Field")}</th>
              <th>{gettext("Was")}</th>
              <th>{gettext("Becomes")}</th>
              <th class="text-right">{gettext("Change, %")}</th>
            </tr>
          </thead>
          <tbody>
            <%= for {row, n} <- Enum.with_index(@view.rows) do %>
              <tr :for={{change, index} <- Enum.with_index(row.changes)} class="align-top">
                <td :if={index == 0} rowspan={length(row.changes)}>
                  <.preview_item row={row} id={"#{@id}-row-#{n}"} />
                </td>
                <td class="font-mono text-xs">{change.field}</td>
                <td class="tabular-nums">{show(change.from)}</td>
                <td class="tabular-nums">{show(change.to)}</td>
                <td class="text-right tabular-nums">
                  {if change.pct, do: change.pct <> "%", else: "—"}
                </td>
              </tr>
              <tr :if={row.changes == []} class="align-top">
                <td colspan="5">
                  <.preview_item row={row} id={"#{@id}-row-#{n}"} />
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>

      <div
        :if={@view.hidden > 0}
        id={@id <> "-truncated"}
        role="alert"
        class="alert alert-warning text-sm"
      >
        <.icon name="hero-exclamation-triangle" class="w-5 h-5" />
        <span>
          {gettext(
            "The preview is cut: %{count} rows are not shown. Confirming runs the whole operation, not only the rows shown.",
            count: @view.hidden
          )}
        </span>
      </div>

      <details
        :if={@view.technical}
        id={@id <> "-technical"}
        phx-mounted={Phoenix.LiveView.JS.ignore_attributes(["open"])}
        class="rounded bg-base-200 p-3"
      >
        <summary class="cursor-pointer text-sm font-medium">
          {gettext("Technical details (JSON)")}
        </summary>
        <div :if={@tool} class="mt-2 font-mono text-xs text-base-content/70">{@tool}</div>
        <pre class="mt-1 max-h-72 overflow-auto whitespace-pre-wrap text-xs">{json_text(@view.technical)}</pre>
      </details>
    </div>
    """
  end

  @doc """
  One row of a preview, as `PhoenixKit.API.Approvals.View.preview/1` reads it: its label,
  the action badge, the error and its reasons, the warnings. The cell the table puts in its
  "Item" column.
  """
  attr :row, :map, required: true
  attr :id, :string, required: true

  def preview_item(assigns) do
    ~H"""
    <div id={@id}>
      <div class="font-medium">{@row.label}</div>
      <div :if={@row.sub} class="font-mono text-xs text-base-content/60">{@row.sub}</div>
      <div
        :if={action_badge?(@row) || @row.error}
        class="mt-1 flex flex-wrap items-center gap-1 text-sm"
      >
        <span :if={action_badge?(@row)} id={@id <> "-action"} class="badge badge-ghost badge-sm">
          {row_action(@row.action)}
        </span>
        <span
          :if={@row.error}
          id={@id <> "-error"}
          class="inline-flex flex-wrap items-center gap-1 text-error"
        >
          <span :if={@row.error_code} class="badge badge-error badge-outline badge-sm font-mono">
            {@row.error_code}
          </span>
          {@row.error}
        </span>
      </div>
      <ul
        :if={@row.error_reasons != []}
        id={@id <> "-reasons"}
        class="mt-1 list-disc space-y-0.5 pl-5 text-xs text-error"
      >
        <li :for={reason <- @row.error_reasons}>{reason}</li>
      </ul>
      <div :for={warning <- @row.warnings} class="mt-1 flex items-start gap-1 text-xs text-warning">
        <.icon name="hero-exclamation-triangle" class="w-3.5 h-3.5 mt-0.5 shrink-0" />
        <span>{warning}</span>
      </div>
    </div>
    """
  end

  # The error of a row says that it failed; an "error" badge next to it would say it twice.
  defp action_badge?(%{action: nil}), do: false
  defp action_badge?(%{action: "error", error: error}), do: error == nil
  defp action_badge?(_row), do: true

  @doc "A value as indented JSON, not Elixir terms: a person reads the keys an API client reads."
  @spec json_text(term()) :: String.t()
  def json_text(term), do: Jason.encode!(term, pretty: true)

  @doc "A value of a change (\"Was\" or \"Becomes\") as text; nothing is a dash."
  @spec show(term()) :: String.t()
  def show(nil), do: "—"
  def show(value) when is_binary(value), do: value
  def show(value) when is_number(value) or is_boolean(value), do: to_string(value)
  def show(value), do: Jason.encode!(value)

  @doc """
  "rows 3, update 2": the totals of a preview, or the numbers of a result
  (`PhoenixKit.API.Approvals.View.facts/1`), as one phrase.
  """
  @spec sentence([{String.t(), term()}]) :: String.t()
  def sentence(facts) do
    Enum.map_join(facts, ", ", fn
      {key, true} -> fact_label(key)
      {key, value} -> fact_label(key) <> " " <> to_string(value)
    end)
  end

  # The counts of what was or will be done, in words; a key nobody here knows is shown as the
  # tool wrote it.
  defp fact_label(key) when key in ["create", "created"],
    do: pgettext("approval summary", "created")

  defp fact_label(key) when key in ["update", "updated"],
    do: pgettext("approval summary", "updated")

  defp fact_label(key) when key in ["delete", "deleted"],
    do: pgettext("approval summary", "deleted")

  defp fact_label(key) when key in ["remove", "removed"],
    do: pgettext("approval summary", "removed")

  defp fact_label("unchanged"), do: pgettext("approval summary", "unchanged")

  defp fact_label(key) when key in ["skip", "skipped"],
    do: pgettext("approval summary", "skipped")

  defp fact_label("error"), do: pgettext("approval summary", "error")
  defp fact_label(key), do: key |> String.replace(["_", "."], " ") |> String.trim()

  # What a row of a preview will do, as a short badge: the preview is of something still
  # waiting for a decision, so these are not the past tense of the counts above. Tools write
  # either form ("update" and "updated"); a word nobody here knows is shown as the tool wrote
  # it, cleaned up like a count word.
  defp row_action(action) when action in ["create", "created"],
    do: pgettext("approval row action", "create")

  defp row_action(action) when action in ["update", "updated"],
    do: pgettext("approval row action", "update")

  defp row_action(action) when action in ["delete", "deleted"],
    do: pgettext("approval row action", "delete")

  defp row_action(action) when action in ["remove", "removed"],
    do: pgettext("approval row action", "remove")

  defp row_action(action) when action in ["skip", "skipped"],
    do: pgettext("approval row action", "skip")

  defp row_action("unchanged"), do: pgettext("approval row action", "unchanged")
  defp row_action("error"), do: pgettext("approval row action", "error")
  defp row_action(action), do: action |> String.replace(["_", "."], " ") |> String.trim()
end
