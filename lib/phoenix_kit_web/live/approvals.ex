defmodule PhoenixKitWeb.Live.Approvals do
  @moduledoc """
  Approvals: the queue of dangerous operations from API keys that need a person's approval
  (the approval path of the dangerous-operation flow), at `/admin/approvals` and in the
  admin menu with the number of approvals the viewer may decide.

  Shows the approvals the person may decide (an Owner: all; the creator of a key: the
  approvals of their keys for tools they hold the permission of) and the latest decided
  ones. **Approve** runs the operation, as the key's owner, in a task of
  `PhoenixKit.TaskSupervisor` that the page awaits with `start_async/3` (a long batch
  does not freeze the page, and a page that goes away does not stop it half-way);
  **Reject** discards it. Gated by the `api` permission
  (`PhoenixKitWeb.Users.Auth`'s view map).

  ## What a card says

  The tool's own title and the number of rows, the key and its owner, when it was
  requested and how long it waits. The preview is read from the shape every module's tools
  share (`PhoenixKit.API.Approvals.View`): a table of item, field, was, becomes and the
  change in percent, the warnings, the totals as a sentence. What does not fit that shape is
  kept, whole, under "Technical details". Once decided, the card stays where it was and says
  in words what became of the operation, and so does the "Recently decided" list.

  ## Rights are checked on the server

  Every event re-reads the person's rights from the database
  (`PhoenixKit.API.Access.fresh_scope/1`): the scope captured at mount can be stale.
  `PhoenixKit.API.Approvals.approve/3` and `reject/3` check again that the person may
  decide *this* approval, and an approval id the person may not decide answers
  `:forbidden`, however the event was made.

  The lists reload whenever any approval changes (`{:api_approval_changed, id}` on the
  topic of `PhoenixKit.API.Approvals`).
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.API.Access
  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Approvals.View
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Registry
  alias PhoenixKit.PubSub.Manager, as: PubSub
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Utils.Routes

  @recent 20

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: PubSub.subscribe(Approvals.topic())

    socket =
      socket
      |> assign(:page_title, gettext("Approvals"))
      |> assign(
        :page_subtitle,
        gettext(
          "Operations from keys that need a person's approval wait here. Nothing runs until you approve it."
        )
      )
      |> assign(:project_title, Settings.get_project_title())
      |> assign(
        :current_path,
        Routes.path("/admin/approvals", locale: socket.assigns.current_locale_base)
      )
      |> assign(:api_scope, socket.assigns.phoenix_kit_current_scope)
      |> assign(:busy, nil)
      |> assign(:settled, %{})
      |> load()

    {:ok, socket}
  end

  # ── Events ───────────────────────────────────────────────────────

  @impl true
  def handle_event("approve", %{"uuid" => uuid}, socket) when is_binary(uuid) do
    case {socket.assigns.busy, Access.fresh_scope(socket.assigns.phoenix_kit_current_scope)} do
      {nil, {:ok, scope}} ->
        {:noreply,
         socket
         |> assign(:api_scope, scope)
         |> assign(:busy, uuid)
         |> run(uuid)
         |> start_async(:approve, fn -> approve_detached(uuid, scope) end)}

      {nil, :error} ->
        {:noreply, put_flash(socket, :error, gettext("You are not allowed to do that."))}

      {_busy, _scope} ->
        {:noreply, socket}
    end
  end

  def handle_event("reject", %{"uuid" => uuid}, socket) when is_binary(uuid) do
    case Access.fresh_scope(socket.assigns.phoenix_kit_current_scope) do
      {:ok, scope} ->
        socket = assign(socket, :api_scope, scope)

        case Approvals.reject(uuid, scope) do
          {:ok, row} ->
            {:noreply,
             socket |> settle(row) |> put_flash(:info, gettext("The approval was rejected."))}

          {:error, reason} ->
            {:noreply, socket |> load() |> put_flash(:error, error_text(reason))}
        end

      :error ->
        {:noreply, put_flash(socket, :error, gettext("You are not allowed to do that."))}
    end
  end

  def handle_event(_event, _params, socket) do
    {:noreply, put_flash(socket, :error, gettext("That action is not available."))}
  end

  @impl true
  def handle_async(:approve, {:ok, result}, socket) do
    case result do
      {:ok, row} ->
        {:noreply, socket |> finish_run() |> settle(row) |> flash_result(row)}

      {:error, reason} ->
        {:noreply, socket |> finish_run() |> reload() |> put_flash(:error, error_text(reason))}
    end
  end

  def handle_async(:approve, {:exit, _reason}, socket) do
    {:noreply,
     socket
     |> finish_run()
     |> reload()
     |> put_flash(:error, gettext("The approval could not be processed."))}
  end

  @impl true
  def handle_info({:api_approval_changed, _id}, socket), do: {:noreply, reload(socket)}
  def handle_info(_other, socket), do: {:noreply, socket}

  # ── State ────────────────────────────────────────────────────────

  # Only the waiter belongs to the page. The operation runs in a supervised task that is
  # not linked to it, so a closed tab, a navigation or a dropped socket cannot stop a
  # destructive batch part-way. If the task itself crashes, `Task.await/2`
  # exits and `handle_async(:approve, {:exit, _}, _)` reports it.
  defp approve_detached(uuid, scope) do
    PhoenixKit.TaskSupervisor
    |> Task.Supervisor.async_nolink(fn -> Approvals.approve(uuid, scope) end)
    |> Task.await(:infinity)
  end

  # The cards, oldest request first: the approvals still waiting, and the ones this page
  # has just decided, which keep their place and say what became of them. The recent list
  # is the other decided ones.
  defp load(socket) do
    scope = socket.assigns.api_scope
    settled = socket.assigns.settled

    pending =
      scope
      |> Approvals.list_pending()
      |> Enum.reject(&Map.has_key?(settled, &1.approval.uuid))
      |> decorate(:pending)

    recent =
      scope
      |> Approvals.list_recent(@recent)
      |> Enum.reject(&Map.has_key?(settled, &1.approval.uuid))
      |> decorate(:decided)

    cards =
      (pending ++ Map.values(settled))
      |> Enum.sort_by(
        &{DateTime.to_unix(&1.approval.inserted_at, :microsecond), &1.approval.uuid}
      )

    socket
    |> assign(:cards, cards)
    |> assign(:recent, recent)
  end

  # The lists, after the person's rights were read again: someone who lost `api` sees nothing.
  defp reload(socket) do
    case Access.fresh_scope(socket.assigns.phoenix_kit_current_scope) do
      {:ok, scope} ->
        socket |> assign(:api_scope, scope) |> load()

      :error ->
        socket
        |> assign(:settled, %{})
        |> assign(:cards, [])
        |> assign(:recent, [])
    end
  end

  # An approval being run is no longer pending, so the lists would drop its card at the
  # next reload: it is kept as a card that says it is running, until the result comes.
  defp run(socket, uuid) do
    case Enum.find(socket.assigns.cards, &(&1.approval.uuid == uuid)) do
      nil ->
        socket

      card ->
        running = %{card | state: :running, outcome: outcome(%{status: "executing"})}
        assign(socket, :settled, Map.put(socket.assigns.settled, uuid, running))
    end
  end

  # The run is over, whatever it came to: the card stops being a running one.
  defp finish_run(socket) do
    socket
    |> assign(:settled, Map.delete(socket.assigns.settled, socket.assigns.busy))
    |> assign(:busy, nil)
  end

  # An approval this page just decided stays on its card, which now carries the outcome.
  defp settle(socket, %Confirmation{uuid: uuid} = row) do
    case Enum.find(socket.assigns.cards, &(&1.approval.uuid == uuid)) do
      nil ->
        load(socket)

      card ->
        [settled] = decorate([%{card | approval: row}], :decided)
        socket |> assign(:settled, Map.put(socket.assigns.settled, uuid, settled)) |> load()
    end
  end

  # The title of the tool, the key's owner, who decided and the preview read for the page.
  defp decorate(entries, state) do
    people = people(entries)
    titles = titles(entries)

    for %{approval: approval, key: key} = entry <- entries do
      entry
      |> Map.put(:state, state)
      |> Map.put(:title, Map.fetch!(titles, approval.tool))
      |> Map.put(:owner, Map.get(people, key.user_uuid))
      |> Map.put(:decider, Map.get(people, approval.decided_by_uuid))
      |> Map.put(:view, View.preview(approval.preview))
      |> Map.put(:outcome, if(state == :decided, do: outcome(approval)))
    end
  end

  defp people(entries) do
    entries
    |> Enum.flat_map(&[&1.key.user_uuid, &1.approval.decided_by_uuid])
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
    |> Auth.get_users_by_uuids()
    |> Map.new(&{&1.uuid, person_name(&1)})
  end

  defp person_name(%User{email: email} = user) do
    case User.full_name(user) do
      name when is_binary(name) and name != "" -> name
      _no_name -> email
    end
  end

  # What the tool calls itself; a tool that is gone (its module switched off) keeps its name.
  defp titles(entries) do
    entries
    |> Enum.map(& &1.approval.tool)
    |> Enum.uniq()
    |> Map.new(fn name ->
      case Registry.find(name, :admin) do
        {:ok, %{title: title}} when is_binary(title) and title != "" -> {name, title}
        _gone -> {name, name}
      end
    end)
  end

  defp flash_result(socket, %{status: "executed"}),
    do: put_flash(socket, :info, gettext("The approval was executed."))

  defp flash_result(socket, %{status: "stale"}),
    do:
      put_flash(
        socket,
        :error,
        gettext(
          "The values changed since the request, so nothing was written. Ask the program to try again."
        )
      )

  defp flash_result(socket, %{status: "failed"} = row),
    do:
      put_flash(
        socket,
        :error,
        gettext("The operation could not run: %{detail}", detail: failure_detail(row))
      )

  defp flash_result(socket, _other), do: socket

  defp failure_detail(%{result: %{"error" => %{"detail" => detail}}}) when is_binary(detail),
    do: detail

  defp failure_detail(_row), do: ""

  defp error_text(:not_found), do: gettext("That approval was not found.")
  defp error_text(:forbidden), do: gettext("You are not allowed to decide this approval.")
  defp error_text(:not_pending), do: gettext("That approval is no longer waiting.")
  defp error_text(:expired), do: gettext("That approval has expired.")

  # ── Template helpers ─────────────────────────────────────────────

  attr :row, :map, required: true
  attr :id, :string, required: true

  defp preview_item(assigns) do
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

  # JSON, not Elixir terms: the approver reads the same keys an API client reads.
  defp json_text(term), do: Jason.encode!(term, pretty: true)

  defp show(nil), do: "—"
  defp show(value) when is_binary(value), do: value
  defp show(value) when is_number(value) or is_boolean(value), do: to_string(value)
  defp show(value), do: Jason.encode!(value)

  # "rows 3, update 2": the totals of a preview, or the numbers of a result, as one phrase.
  defp sentence(facts) do
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

  defp expires_in(%DateTime{} = expires_at) do
    seconds = DateTime.diff(expires_at, DateTime.utc_now(), :second)

    cond do
      seconds < 60 -> gettext("Expires in less than a minute")
      seconds < 3_600 -> gettext("Expires in %{count} min", count: div(seconds, 60))
      seconds < 86_400 -> gettext("Expires in %{count} h", count: div(seconds, 3_600))
      true -> gettext("Expires in %{count} d", count: div(seconds, 86_400))
    end
  end

  defp expires_in(_other), do: "—"

  defp status_label("executed"), do: gettext("Executed")
  defp status_label("failed"), do: gettext("Failed")
  defp status_label("rejected"), do: gettext("Rejected")
  defp status_label("stale"), do: gettext("Stale")
  defp status_label("expired"), do: gettext("Expired")
  defp status_label(_approved_or_executing), do: gettext("Running")

  defp status_class("executed"), do: "badge-success"
  defp status_class("failed"), do: "badge-error"
  defp status_class(status) when status in ["approved", "executing"], do: "badge-info"
  defp status_class(_other), do: "badge-ghost"

  # What became of a decided approval, in words: the alert's class, the sentence and the
  # detail. The detail is the tool's own explanation of a failure, which is English.
  defp outcome(%{status: "executed", result: result}) do
    case View.facts(result) do
      [] -> alert("alert-success", gettext("Done."))
      facts -> alert("alert-success", gettext("Done: %{summary}", summary: sentence(facts)))
    end
  end

  defp outcome(%{status: "stale"}),
    do:
      alert(
        "alert-warning",
        gettext("Not executed: the data changed since the request; nothing was written.")
      )

  defp outcome(%{status: "failed"} = approval) do
    detail = if failure_detail(approval) != "", do: failure_detail(approval)
    alert("alert-error", gettext("Failed: %{code}", code: failure_code(approval)), detail)
  end

  defp outcome(%{status: "rejected"}),
    do: alert("alert-info", gettext("Rejected: nothing was run."))

  defp outcome(%{status: "expired"}),
    do: alert("alert-info", gettext("Expired: nobody decided in time, nothing was run."))

  defp outcome(_approved_or_executing), do: alert("alert-info", gettext("Running."))

  defp alert(class, text, detail \\ nil), do: %{class: class, text: text, detail: detail}

  defp failure_code(%{result: %{"error" => %{"code" => code}}}) when is_binary(code), do: code
  defp failure_code(_approval), do: "unknown"
end
