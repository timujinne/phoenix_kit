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

  Does not depend on Storage; any `allow_upload` can use it.

  ## Wire protocol

  Events from the hook (all carry `"upload"`): `pk_upload_pick` (a file was
  chosen, with its context), `pk_upload_resume` (the browser holds leftovers;
  the reply says what to do with each), `pk_upload_resume_click` and
  `pk_upload_discard` (the buttons of the ask row). Events to the hook:
  `pk-upload-received`, `-stored`, `-rejected`, `-feed`, `-drop`.
  """

  import Phoenix.Component, only: [assign: 3, upload_errors: 2]
  import Phoenix.LiveView

  alias Phoenix.LiveView.UploadConfig
  alias Phoenix.LiveView.UploadEntry

  @events ~w(pk_upload_pick pk_upload_resume pk_upload_resume_click pk_upload_discard)
  @max_string 512
  @max_keys 200
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
    |> attach_hook({:pk_resumable, name}, :after_render, &reject_new(&1, name))
    |> publish(name)
  end

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
      %{pending_at: at} when is_integer(at) -> now() - at < @pending_ttl_ms
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
    |> update_state(name, &%{&1 | pending_at: nil})
    |> push_event("pk-upload-received", %{upload: Atom.to_string(name), key: client_key(entry)})
  end

  defp finish(socket, name, entry_or_key, event) do
    key = if is_binary(entry_or_key), do: entry_or_key, else: client_key(entry_or_key)

    socket
    |> update_state(name, &forget_context(&1, key))
    |> push_event(event, %{upload: Atom.to_string(name), key: key})
  end

  # Entries LiveView turned away never open an upload channel, so `progress:`
  # does not hear of them: they are found among the entries of every event, in
  # time to be cancelled before the host's own handler (and the render) see them,
  # and again after every render for the ones that came in without an event the
  # hook sees (a cancel made then shows from the next render on).
  defp reject_new(socket, name) do
    with %{} = state <- get_state(socket, name),
         %UploadConfig{} = conf <- socket.assigns[:uploads][name] do
      fresh =
        for entry <- conf.entries,
            not MapSet.member?(state.rejected_seen, entry.ref),
            errors = upload_errors(conf, entry),
            errors != [],
            do: {entry, errors}

      Enum.reduce(fresh, socket, fn {entry, errors}, acc ->
        acc
        |> update_state(name, &%{&1 | rejected_seen: MapSet.put(&1.rejected_seen, entry.ref)})
        |> on_rejected(name, entry, errors)
        |> maybe_cancel(name, entry)
        |> rejected(name, entry)
      end)
    else
      _ -> socket
    end
  end

  defp on_rejected(socket, name, entry, errors) do
    case get_state(socket, name).opts[:on_rejected] do
      fun when is_function(fun, 3) -> fun.(socket, entry, errors)
      _ -> put_flash(socket, :error, default_reason(entry, errors))
    end
  end

  defp default_reason(entry, errors) do
    Gettext.dgettext(PhoenixKitWeb.Gettext, "default", "%{name}: %{reason}",
      name: entry.client_name,
      reason: Enum.map_join(errors, ", ", &error_text/1)
    )
  end

  defp error_text(:too_large),
    do: Gettext.dgettext(PhoenixKitWeb.Gettext, "default", "file too large")

  defp error_text(:not_accepted),
    do: Gettext.dgettext(PhoenixKitWeb.Gettext, "default", "file type not accepted")

  defp error_text(other), do: to_string(other)

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
      |> then(&%{&1 | private: Map.put(&1.private, :pk_resumable_guard, true)})
    end
  end

  defp guard(event, %{"upload" => upload}, socket) when event in @events do
    if Enum.any?(resumable_names(socket), &(Atom.to_string(&1) == upload)),
      do: {:cont, socket},
      else: {:halt, %{error: "not_attached"}, socket}
  end

  defp guard(_event, _params, socket), do: {:cont, socket}

  defp handle_event(name, event, %{"upload" => upload} = params, socket) when event in @events do
    if upload == Atom.to_string(name) do
      socket = reject_new(socket, name)
      {reply, socket} = handle(event, name, params, socket)
      {:halt, reply, socket}
    else
      {:cont, socket}
    end
  end

  # Every other event: the entries it brought may include refused ones.
  defp handle_event(name, _event, _params, socket), do: {:cont, reject_new(socket, name)}

  defp handle("pk_upload_pick", name, params, socket) do
    items = items(params, socket, name)
    {%{}, update_state(socket, name, &put_contexts(&1, items))}
  end

  defp handle("pk_upload_resume", name, params, socket) do
    items = items(params, socket, name)
    conf = socket.assigns.uploads[name]

    live =
      for e <- conf.entries, e.valid?, not e.cancelled?, into: MapSet.new(), do: client_key(e)

    free = max(conf.max_entries - Enum.count(conf.entries, & &1.valid?), 0)
    policy = get_state(socket, name).opts[:policy] || (&default_policy/3)

    {decided, _free} =
      Enum.map_reduce(items, free, fn item, free ->
        decide(item, MapSet.member?(live, item.key), policy.(socket, item, free), free)
      end)

    ids = fn what -> for {^what, item} <- decided, do: item.id end
    asked = for {:ask, item} <- decided, do: Map.take(item, [:id, :name, :size, :has_bytes])
    keep = for {d, item} <- decided, d != :drop, do: item

    socket =
      socket
      |> update_state(name, fn st ->
        st = put_contexts(st, keep)
        %{st | ask: asked, pending_at: if(ids.(:auto) != [], do: now(), else: st.pending_at)}
      end)
      |> publish(name)

    {%{auto: ids.(:auto), queued: ids.(:queued), ask: ids.(:ask), drop: ids.(:drop)}, socket}
  end

  defp handle("pk_upload_resume_click", name, _params, socket) do
    st = get_state(socket, name)
    ids = Enum.map(st.ask, & &1.id)

    socket =
      socket
      |> update_state(
        name,
        &%{&1 | ask: [], pending_at: if(ids == [], do: &1.pending_at, else: now())}
      )
      |> publish(name)
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
    %{contexts: %{}, pending_at: nil, ask: [], rejected_seen: MapSet.new(), opts: opts}
  end

  defp put_contexts(st, items) do
    Enum.reduce(items, st, fn item, acc ->
      if is_binary(item.context) and
           (Map.has_key?(acc.contexts, item.key) or map_size(acc.contexts) < @max_keys) do
        by_seq = Map.get(acc.contexts, item.key, %{})

        %{
          acc
          | contexts: Map.put(acc.contexts, item.key, Map.put(by_seq, item.seq, item.context))
        }
      else
        acc
      end
    end)
  end

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
      state -> put_state(socket, name, fun.(state))
    end
  end

  # What `<.resumable_upload>` reads: which uploads are resumable, and the files
  # waiting for a button press.
  defp publish(socket, name) do
    ask = get_state(socket, name).ask
    current = Map.get(socket.assigns, :resumable_uploads, %{})
    assign(socket, :resumable_uploads, Map.put(current, name, %{ask: ask}))
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc false
  def client_key(entry),
    do: "#{entry.client_name}|#{entry.client_size}|#{entry.client_last_modified}"
end
