defmodule PhoenixKitWeb.ResumableUploads do
  @moduledoc """
  Uploads that survive the page being sent to the background.

  On a phone or tablet, choosing "Camera" in a file input puts the browser in
  the background; the LiveView socket drops, and a few seconds later the page
  remounts with nothing left of the transfer. This module, together with the
  `ResumableUpload` JavaScript hook, keeps every picked file in the browser
  until the host has saved it, and carries a lost transfer on by itself after
  the reconnect.

  ## Using it

  Replace `allow_upload/3` with `allow_resumable_upload/4` and wrap the file
  input in `<.resumable_upload>`:

      def mount(_params, _session, socket) do
        {:ok,
         allow_resumable_upload(socket, :photos, [accept: ~w(.jpg .png), auto_upload: true],
           on_rejected: &show_reason/3
         )}
      end

      <form id="photos-form" phx-change="validate" phx-submit="save">
        <.resumable_upload
          upload={@uploads.photos}
          resumable={@resumable_uploads}
          scope={"photos|\#{@record.uuid}"}
          user={@current_user.uuid}
          context={@kind}
        >
          <.live_file_input upload={@uploads.photos} />
        </.resumable_upload>
      </form>

      def handle_event("save", _params, socket) do
        {socket, _files} =
          ResumableUploads.consume_uploaded_entries(socket, :photos, fn %{path: path}, entry ->
            kind = ResumableUploads.resume_context(socket, entry) || "default"

            case MyApp.Files.store(path, kind) do
              {:ok, file} -> {:stored, file}
              {:error, :unsupported} -> {:rejected, nil}
              {:error, _} -> {:retry, nil}
            end
          end)

        {:noreply, socket}
      end

  ## Rules for the host

    * **`scope` is required** and has no default. It names what the files
      belong to (`"photos|<record uuid>"`), so a file picked for one record is
      never offered on the page of another. It must not be the URL: a sticky
      LiveView lives on many pages.
    * **The form needs an `id` and `phx-change`.** LiveView's form recovery
      clears a file input when a form without them is re-joined, and the
      hook feeds files back through the form's change event.
    * **`context` is untrusted.** It is an opaque string the host puts on the
      hook (a folder, a chat, a tab) that comes back with the file; the browser
      stores it and a client can change it. Check it (`resume_context/2`)
      before using it, exactly as for any parameter.
    * **Delivery is at least once.** If the connection dies between the server
      receiving the bytes and the host answering `stored`, the file arrives
      again. Make saving idempotent (a checksum, a unique key) or accept the
      duplicate.
    * **Say what happened to every file.** Use `consume_uploaded_entries/3`
      with an explicit outcome (`{:stored, v}`, `{:rejected, v}`, `{:retry, v}`),
      or call `stored/3` and `rejected/3` yourself (for example from
      `handle_async/3`). `{:retry, _}` and not answering at all leave the file
      in the browser, to be offered to the person with a button.

    * **Your own sign-out links need `data-pk-logout={user uuid}`** (see
      `logout_user/1`). The files stashed in the browser by that user are
      removed before the request goes out; without a uuid the hook of the page
      is asked, and failing that everything goes. Core's links carry it.
    * **A cancelled file is not carried on.** An entry that disappears from the
      upload without having arrived (`cancel_upload/3`, the cancel button) is
      reported to the browser as rejected, and its stashed copy is deleted.

  Does not depend on Storage; any `allow_upload` can use it.

  ## Wire protocol

  Events from the hook (all carry `"upload"`): `pk_upload_pick` (a file was
  chosen, with its context), `pk_upload_resume` (the browser holds leftovers;
  the reply says what to do with each), `pk_upload_resume_click` and
  `pk_upload_discard` (the buttons of the ask row). Events to the hook:
  `pk-upload-received`, `-stored`, `-rejected`, `-feed`, `-drop`.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  import Phoenix.Component, only: [assign: 3, upload_errors: 2]
  import Phoenix.LiveView

  require Logger

  alias Phoenix.LiveView.UploadConfig
  alias Phoenix.LiveView.UploadEntry
  alias PhoenixKit.Users.Auth.Scope

  @events ~w(pk_upload_pick pk_upload_resume pk_upload_resume_click pk_upload_discard pk_upload_debug)
  @max_string 512
  @max_keys 200
  @max_seqs 20
  # Only these are final refusals the person reads about; the other entry
  # errors (`{:writer_failure, _}`, `:external_client_failure`, …) are failures
  # of the moment: the file stays in the browser, unacknowledged and uncancelled.
  @final_errors [:too_large, :not_accepted]
  @pending_ttl_ms 120_000

  @doc """
  `allow_upload/3` plus the resume machinery.

  `allow_opts` are those of `allow_upload/3`; a `progress:` callback of the
  host is called from inside the wrapper that reports receipt. `resume_opts`:

    * `:policy` — `fun(socket, item, free_slots) -> :auto | :ask | :drop`. Must
      be fast and pure; `item` comes from the browser and is untrusted
      (`%{key, name, size, context, has_bytes, state, attempts, fresh}`).
      Default: `:auto` for a file whose bytes are kept, whose transfer had not
      finished (`state: "pending"`), that is fresh and has had fewer than 3
      tries; `:ask` otherwise (a file the server already received is never
      sent again without a person saying so).
    * `:on_rejected` — `fun(socket, entry, errors) -> socket`, called once for
      an entry LiveView turned away (`:too_large`, `:not_accepted`). Default: an
      error flash with the reason.
    * `:cancel_rejected` — cancel such an entry so it stops holding one of
      `max_entries` slots (default `true`).
  """
  @spec allow_resumable_upload(Phoenix.LiveView.Socket.t(), atom(), keyword(), keyword()) ::
          Phoenix.LiveView.Socket.t()
  def allow_resumable_upload(socket, name, allow_opts, resume_opts \\ []) when is_atom(name) do
    host_progress = Keyword.get(allow_opts, :progress)
    allow_opts = Keyword.put(allow_opts, :progress, progress_wrapper(host_progress))

    socket
    |> allow_upload(name, allow_opts)
    |> put_state(name, new_state(resume_opts))
    |> attach_guard()
    |> attach_hook({:pk_resumable, name}, :handle_event, &handle_event(name, &1, &2, &3))
    |> attach_hook({:pk_resumable, name}, :after_render, &sync_entries(&1, name))
    |> publish(name)
  end

  @doc """
  The uuid of the user a page belongs to, as the value of `data-pk-logout`
  (`""` when there is none). `assigns` is the page's or component's assigns;
  the user is looked up as `:phoenix_kit_current_user`, `:user` or in
  `:phoenix_kit_current_scope`.
  """
  @spec logout_user(map()) :: String.t()
  def logout_user(assigns) when is_map(assigns) do
    user =
      assigns[:phoenix_kit_current_user] || assigns[:user] ||
        Scope.user(assigns[:phoenix_kit_current_scope])

    case user do
      %{uuid: uuid} when not is_nil(uuid) -> to_string(uuid)
      _ -> ""
    end
  end

  @doc """
  True for the config of an upload set up with `allow_resumable_upload/4`.

  A component that renders the hook for an upload it did not set up itself
  (MediaBrowser, for the `parent_uploads` of its host) asks this first: the
  hook's events would reach a LiveView that has no clause for them.
  """
  @spec resumable_config?(term()) :: boolean()
  def resumable_config?(%UploadConfig{progress_event: fun}) when is_function(fun, 3),
    do: Function.info(fun, :module) == {:module, __MODULE__}

  def resumable_config?(_), do: false

  @doc """
  The context the browser stored for `entry` when it was picked, or `nil`.

  `nil` when the browser sent none, when the same file was picked twice with
  different contexts (ambiguous), or when `entry` is not of a resumable upload.
  **Untrusted** — check it before use.
  """
  @spec resume_context(Phoenix.LiveView.Socket.t(), UploadEntry.t()) :: String.t() | nil
  def resume_context(socket, %UploadEntry{} = entry) do
    with %{contexts: contexts} <- get_state(socket, entry.upload_config),
         %{} = by_seq <- Map.get(contexts, client_key(entry)) do
      case by_seq |> Map.values() |> Enum.uniq() do
        [context] -> context
        _ -> nil
      end
    else
      _ -> nil
    end
  end

  @doc "The host saved the file: the browser may forget its copy."
  @spec stored(Phoenix.LiveView.Socket.t(), atom(), UploadEntry.t() | String.t()) ::
          Phoenix.LiveView.Socket.t()
  def stored(socket, name, entry_or_key),
    do: finish(socket, name, entry_or_key, "pk-upload-stored")

  @doc "The host turned the file down for good: the browser may forget its copy."
  @spec rejected(Phoenix.LiveView.Socket.t(), atom(), UploadEntry.t() | String.t()) ::
          Phoenix.LiveView.Socket.t()
  def rejected(socket, name, entry_or_key),
    do: finish(socket, name, entry_or_key, "pk-upload-rejected")

  @doc """
  Like `Phoenix.LiveView.consume_uploaded_entries/3`, but `fun` (arity 2:
  `meta, entry`) returns an explicit outcome:

    * `{:stored, value}` — the file is saved (`stored/3` is sent);
    * `{:rejected, value}` — final refusal (`rejected/3` is sent);
    * `{:retry, value}` — temporary failure; nothing is sent, the browser keeps
      the file and offers it again.

  Returns `{socket, values}`. The outcome is never inferred from `{:ok, _}` or
  `{:error, _}`: a host that stored nothing must not say it did.
  """
  @spec consume_uploaded_entries(Phoenix.LiveView.Socket.t(), atom(), (map(), UploadEntry.t() ->
                                                                         {:stored
                                                                          | :rejected
                                                                          | :retry, term()})) ::
          {Phoenix.LiveView.Socket.t(), [term()]}
  def consume_uploaded_entries(socket, name, fun) when is_function(fun, 2) do
    results =
      Phoenix.LiveView.consume_uploaded_entries(socket, name, fn meta, entry ->
        {outcome, value} = fun.(meta, entry)
        {:ok, {outcome, entry, value}}
      end)

    socket =
      Enum.reduce(results, socket, fn
        {:stored, entry, _}, acc -> stored(acc, name, entry)
        {:rejected, entry, _}, acc -> rejected(acc, name, entry)
        {:retry, _entry, _}, acc -> acc
      end)

    {socket, Enum.map(results, &elem(&1, 2))}
  end

  @doc """
  True from the moment a lost transfer was set to continue by itself until its
  entry has arrived (or two minutes passed). A host can keep "Send" disabled.
  """
  @spec pending?(Phoenix.LiveView.Socket.t(), atom()) :: boolean()
  def pending?(socket, name) do
    case get_state(socket, name) do
      %{outstanding: list} -> live_outstanding(list) != []
      _ -> false
    end
  end

  # ── progress and rejections ───────────────────────────────────────────────

  defp progress_wrapper(host_progress) do
    fn name, entry, socket ->
      socket = if entry.done?, do: received(socket, name, entry), else: socket

      case host_progress do
        nil -> {:noreply, socket}
        fun when is_function(fun, 3) -> fun.(name, entry, socket)
      end
    end
  end

  defp received(socket, name, entry) do
    socket
    |> update_state(name, fn st ->
      st |> drop_outstanding() |> Map.update!(:refs, &Map.delete(&1, entry.ref))
    end)
    |> push_event("pk-upload-received", %{upload: Atom.to_string(name), key: client_key(entry)})
  end

  defp finish(socket, name, entry_or_key, event) do
    key = if is_binary(entry_or_key), do: entry_or_key, else: client_key(entry_or_key)

    socket
    |> update_state(name, &forget_context(&1, key))
    |> push_event(event, %{upload: Atom.to_string(name), key: key})
  end

  # Two things are found among the entries of every event (before the host's
  # own handler sees them) and again after every render (for what came in with
  # no event the hook sees):
  #
  #   * entries LiveView turned away — they never open an upload channel, so
  #     `progress:` does not hear of them: reported to the host, cancelled
  #     (unless it opted out) and acknowledged to the browser as rejected;
  #   * entries that were under way and have vanished without being received —
  #     the person cancelled them: the browser must not carry them on later, so
  #     they are acknowledged as rejected too.
  #
  # A cancel made in `after_render` shows from the next render on.
  defp sync_entries(socket, name) do
    with %{} <- get_state(socket, name),
         %UploadConfig{} <- socket.assigns[:uploads][name] do
      socket |> reject_new(name) |> forget_cancelled(name)
    else
      _ -> socket
    end
  end

  defp reject_new(socket, name) do
    state = get_state(socket, name)
    conf = socket.assigns.uploads[name]

    fresh =
      for entry <- conf.entries,
          not MapSet.member?(state.rejected_seen, entry.ref),
          errors = Enum.filter(upload_errors(conf, entry), &(&1 in @final_errors)),
          errors != [],
          do: {entry, errors}

    Enum.reduce(fresh, socket, fn {entry, errors}, acc ->
      acc
      |> update_state(name, fn st ->
        drop_outstanding(%{st | rejected_seen: MapSet.put(st.rejected_seen, entry.ref)})
      end)
      |> on_rejected(name, entry, errors)
      |> maybe_cancel(name, entry)
      |> rejected(name, entry)
    end)
  end

  defp forget_cancelled(socket, name) do
    conf = socket.assigns.uploads[name]
    present = MapSet.new(conf.entries, & &1.ref)

    {gone, kept} =
      Enum.split_with(get_state(socket, name).refs, fn {ref, _} ->
        not MapSet.member?(present, ref)
      end)

    open =
      for entry <- conf.entries, not entry.done?, upload_errors(conf, entry) == [], into: %{} do
        {entry.ref, client_key(entry)}
      end

    socket = update_state(socket, name, &%{&1 | refs: Map.merge(Map.new(kept), open)})

    Enum.reduce(gone, socket, fn {_ref, key}, acc ->
      acc |> update_state(name, &drop_outstanding/1) |> rejected(name, key)
    end)
  end

  defp on_rejected(socket, name, entry, errors) do
    case get_state(socket, name).opts[:on_rejected] do
      fun when is_function(fun, 3) -> fun.(socket, entry, errors)
      _ -> put_flash(socket, :error, default_reason(entry, errors))
    end
  end

  defp default_reason(entry, errors) do
    gettext("%{name}: %{reason}",
      name: entry.client_name,
      reason: Enum.map_join(errors, ", ", &error_text/1)
    )
  end

  defp error_text(:too_large), do: gettext("file too large")
  defp error_text(:not_accepted), do: gettext("file type not accepted")
  defp error_text(other) when is_atom(other), do: Atom.to_string(other)
  defp error_text(other), do: inspect(other)

  defp maybe_cancel(socket, name, entry) do
    if Keyword.get(get_state(socket, name).opts, :cancel_rejected, true),
      do: cancel_upload(socket, name, entry.ref),
      else: socket
  end

  # ── events from the hook ──────────────────────────────────────────────────

  # An event for an upload nobody attached must not reach the host's own
  # handlers (which have no clause for it): say so and stop.
  defp attach_guard(socket) do
    if Map.has_key?(socket.private, :pk_resumable_guard) do
      socket
    else
      socket
      |> attach_hook(:pk_resumable_guard, :handle_event, &guard/3)
      |> attach_hook(:pk_resumable_expiry, :handle_info, &expire/2)
      |> then(&%{&1 | private: Map.put(&1.private, :pk_resumable_guard, true)})
    end
  end

  defp guard(event, params, socket) when event in @events do
    upload = if is_map(params), do: Map.get(params, "upload")

    if is_binary(upload) and Enum.any?(resumable_names(socket), &(Atom.to_string(&1) == upload)),
      do: {:cont, socket},
      else: {:halt, %{error: "not_attached"}, socket}
  end

  defp guard(_event, _params, socket), do: {:cont, socket}

  defp expire({:pk_resumable_expire, name}, socket) do
    case get_state(socket, name) do
      nil -> {:halt, socket}
      _ -> {:halt, update_state(socket, name, & &1)}
    end
  end

  defp expire(_msg, socket), do: {:cont, socket}

  defp handle_event(name, event, %{"upload" => upload} = params, socket) when event in @events do
    if upload == Atom.to_string(name) do
      socket = sync_entries(socket, name)
      {reply, socket} = handle(event, name, params, socket)
      {:halt, reply, socket}
    else
      {:cont, socket}
    end
  end

  # Every other event: the entries it brought may include refused ones.
  defp handle_event(name, _event, _params, socket), do: {:cont, sync_entries(socket, name)}

  defp handle("pk_upload_pick", name, params, socket) do
    items = items(params, socket, name)
    {socket, dropped} = store_contexts(socket, name, items)
    {if(dropped > 0, do: %{dropped: dropped}, else: %{}), socket}
  end

  # The hook's trace of what it saw (counts only), for reading the order of
  # events on a device that has no console.
  defp handle("pk_upload_debug", name, params, socket) do
    phase = if params["phase"] in ~w(pick stashed scan), do: params["phase"], else: "?"
    n = if is_integer(params["n"]), do: params["n"], else: -1

    Logger.info(
      "ResumableUploads: #{name} #{phase} n=#{n} connected=#{params["connected"] == true}"
    )

    {%{}, socket}
  end

  defp handle("pk_upload_resume", name, params, socket) do
    items = items(params, socket, name)
    conf = socket.assigns.uploads[name]

    live =
      for e <- conf.entries, e.valid?, not e.cancelled?, into: MapSet.new(), do: client_key(e)

    st = get_state(socket, name)
    outstanding = live_outstanding(st.outstanding)
    free = max(conf.max_entries - Enum.count(conf.entries, & &1.valid?) - length(outstanding), 0)
    policy = st.opts[:policy] || (&default_policy/3)

    {decided, _free} =
      Enum.map_reduce(items, free, fn item, free ->
        decide(item, MapSet.member?(live, item.key), policy.(socket, item, free), free)
      end)

    ids = fn what -> for {^what, item} <- decided, do: item.id end
    asked = for {:ask, item} <- decided, do: Map.take(item, [:id, :name, :size, :has_bytes])
    keep = for {d, item} <- decided, d != :drop, do: item

    {socket, _dropped} = store_contexts(socket, name, keep)

    socket =
      socket
      |> update_state(name, fn st ->
        fed = List.duplicate(now(), length(ids.(:auto)))
        %{st | ask: asked, outstanding: outstanding ++ fed}
      end)
      |> publish(name)
      |> schedule_expiry(name, length(ids.(:auto)))

    {%{auto: ids.(:auto), queued: ids.(:queued), ask: ids.(:ask), drop: ids.(:drop)}, socket}
  end

  defp handle("pk_upload_resume_click", name, _params, socket) do
    st = get_state(socket, name)
    conf = socket.assigns.uploads[name]
    outstanding = live_outstanding(st.outstanding)
    free = max(conf.max_entries - Enum.count(conf.entries, & &1.valid?) - length(outstanding), 0)
    {feed, wait} = Enum.split(st.ask, free)
    ids = Enum.map(feed, & &1.id)

    socket =
      socket
      |> update_state(name, fn st ->
        %{st | ask: wait, outstanding: outstanding ++ List.duplicate(now(), length(ids))}
      end)
      |> publish(name)
      |> schedule_expiry(name, length(ids))
      |> push_event("pk-upload-feed", %{upload: Atom.to_string(name), ids: ids})

    {%{}, socket}
  end

  defp handle("pk_upload_discard", name, _params, socket) do
    ids = Enum.map(get_state(socket, name).ask, & &1.id)

    socket =
      socket
      |> update_state(name, &%{&1 | ask: []})
      |> publish(name)
      |> push_event("pk-upload-drop", %{upload: Atom.to_string(name), ids: ids})

    {%{}, socket}
  end

  defp decide(item, true, _answer, free), do: {{:queued, item}, free}
  defp decide(item, false, :auto, free) when free > 0, do: {{:auto, item}, free - 1}
  defp decide(item, false, :auto, free), do: {{:queued, item}, free}
  defp decide(item, false, :ask, free), do: {{:ask, item}, free}
  defp decide(item, false, _drop, free), do: {{:drop, item}, free}

  @doc false
  def default_policy(
        _socket,
        %{has_bytes: true, state: "pending", fresh: true, attempts: a},
        _free
      )
      when a < 3,
      do: :auto

  def default_policy(_socket, _item, _free), do: :ask

  # Untrusted: bounded in count and size, and only what we read.
  defp items(params, socket, name) do
    limit = socket.assigns.uploads[name].max_entries * 4

    params
    |> Map.get("items", [])
    |> List.wrap()
    |> Enum.take(limit)
    |> Enum.flat_map(fn
      %{"key" => key, "seq" => seq} = raw when is_binary(key) and is_binary(seq) ->
        if byte_size(key) <= @max_string and byte_size(seq) <= @max_string,
          do: [sanitize(raw, key, seq)],
          else: []

      _ ->
        []
    end)
  end

  defp sanitize(raw, key, seq) do
    %{
      id: string(raw["id"]) || key <> "#" <> seq,
      key: key,
      seq: seq,
      name: string(raw["name"]) || "file",
      size: if(is_integer(raw["size"]), do: raw["size"], else: 0),
      context: string(raw["context"]),
      has_bytes: raw["has_bytes"] == true,
      state: if(raw["state"] == "received", do: "received", else: "pending"),
      attempts: if(is_integer(raw["attempts"]), do: raw["attempts"], else: 0),
      fresh: raw["fresh"] == true
    }
  end

  defp string(value) when is_binary(value) and byte_size(value) <= @max_string, do: value
  defp string(_), do: nil

  # ── state ─────────────────────────────────────────────────────────────────

  defp new_state(opts) do
    %{
      contexts: %{},
      outstanding: [],
      ask: [],
      refs: %{},
      rejected_seen: MapSet.new(),
      opts: opts
    }
  end

  # Contexts are the client's to send, so there are limits: keys and seqs per
  # key. A context that does not fit is dropped (the host then uses its own
  # default) and the count comes back to the browser and to the log.
  defp store_contexts(socket, name, items) do
    {st, dropped} =
      Enum.reduce(items, {get_state(socket, name), 0}, fn item, {acc, dropped} ->
        by_seq = Map.get(acc.contexts, item.key, %{})

        cond do
          not is_binary(item.context) ->
            {acc, dropped}

          Map.has_key?(by_seq, item.seq) or
              (map_size(by_seq) < @max_seqs and
                 (by_seq != %{} or map_size(acc.contexts) < @max_keys)) ->
            {%{
               acc
               | contexts:
                   Map.put(acc.contexts, item.key, Map.put(by_seq, item.seq, item.context))
             }, dropped}

          true ->
            {acc, dropped + 1}
        end
      end)

    if dropped > 0,
      do:
        Logger.debug("ResumableUploads: #{dropped} context(s) of #{name} dropped, limit reached")

    {put_state(socket, name, st), dropped}
  end

  defp live_outstanding(list), do: Enum.filter(list, &(now() - &1 < pending_ttl()))

  defp pending_ttl,
    do: Application.get_env(:phoenix_kit, :resumable_pending_ttl_ms, @pending_ttl_ms)

  # `pending` is published as a snapshot, so nothing would tell a component
  # that it lapsed when no event follows: ask this process to publish again
  # just after the TTL (answered by the hook attached in `attach_guard/1`).
  defp schedule_expiry(socket, name, count) do
    if count > 0, do: Process.send_after(self(), {:pk_resumable_expire, name}, pending_ttl() + 1)
    socket
  end

  defp drop_outstanding(st),
    do: %{st | outstanding: Enum.drop(live_outstanding(st.outstanding), 1)}

  defp forget_context(st, key) do
    case Map.get(st.contexts, key) do
      nil ->
        st

      by_seq ->
        rest = Map.delete(by_seq, by_seq |> Map.keys() |> Enum.min())

        contexts =
          if rest == %{}, do: Map.delete(st.contexts, key), else: Map.put(st.contexts, key, rest)

        %{st | contexts: contexts}
    end
  end

  defp resumable_names(socket), do: socket.private |> Map.get(:pk_resumable, %{}) |> Map.keys()
  defp get_state(socket, name), do: socket.private |> Map.get(:pk_resumable, %{}) |> Map.get(name)

  defp put_state(socket, name, state) do
    all = socket.private |> Map.get(:pk_resumable, %{}) |> Map.put(name, state)
    %{socket | private: Map.put(socket.private, :pk_resumable, all)}
  end

  defp update_state(socket, name, fun) do
    case get_state(socket, name) do
      nil -> socket
      state -> socket |> put_state(name, fun.(state)) |> publish(name)
    end
  end

  # What `<.resumable_upload>` reads: which uploads are resumable, the files
  # waiting for a button press, and whether an automatic continuation is
  # pending (`pending?/2`, for a component that cannot see this socket's state).
  defp publish(socket, name) do
    ask = get_state(socket, name).ask
    current = Map.get(socket.assigns, :resumable_uploads, %{})
    entry = %{ask: ask, pending: pending?(socket, name)}
    assign(socket, :resumable_uploads, Map.put(current, name, entry))
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc false
  def client_key(entry),
    do: "#{entry.client_name}|#{entry.client_size}|#{entry.client_last_modified}"
end
