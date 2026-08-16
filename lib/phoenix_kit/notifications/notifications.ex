defmodule PhoenixKit.Notifications do
  @moduledoc """
  Per-user notifications driven by `PhoenixKit.Activity`.

  When an activity is logged with a `target_uuid` that differs from the
  `actor_uuid`, a row is inserted into `phoenix_kit_notifications` for the
  target user. The user sees it in the bell dropdown (`count_unread/1`,
  `recent_for_user/2`) and in the inbox at `/notifications` (`list_for_user/2`).
  Each row carries its own `seen_at` and `dismissed_at` — the same activity
  can be "seen but not dismissed" for one user and "unseen" for another.

  The whole feature is gated by the global `notifications_enabled` setting
  (default `"true"`); when `"false"`, `maybe_create_from_activity/1` is a no-op.

  Registered as a core toggleable module (`use PhoenixKit.Module`) so it
  appears on the admin Modules page and contributes the `/admin/notifications`
  overview tab. The module enable/disable flips the same
  `notifications_enabled` kill-switch `enabled?/0` reads.
  """

  use PhoenixKit.Module

  import Ecto.Query, warn: false
  require Logger

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.Dashboard.Tab
  alias PhoenixKit.Notifications.ChannelConfig
  alias PhoenixKit.Notifications.DeliveryWorker
  alias PhoenixKit.Notifications.Events
  alias PhoenixKit.Notifications.Notification
  alias PhoenixKit.Notifications.Prefs
  alias PhoenixKit.Notifications.Routing
  alias PhoenixKit.Notifications.Types
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.Date, as: UtilsDate

  # ── Creation ─────────────────────────────────────────────────────────

  @doc """
  Inserts a notification for the activity's target user, if the rules allow it.

  Returns one of:
    * `{:ok, %Notification{}}` — row created; broadcast on the per-user topic
    * `{:ok, :skipped}` — filtered out (no target, self-action, feature disabled)
    * `{:error, changeset}` — insert failed (logged, never raised)
  """
  def maybe_create_from_activity(%Entry{} = entry) do
    cond do
      not enabled?() -> {:ok, :skipped}
      is_nil(entry.target_uuid) -> {:ok, :skipped}
      entry.target_uuid == entry.actor_uuid -> {:ok, :skipped}
      true -> route_activity(entry)
    end
  rescue
    e ->
      Logger.warning("Notifications.maybe_create_from_activity failed: #{inspect(e)}")
      {:ok, :skipped}
  end

  @doc """
  Fans ONE committed activity entry out to MANY users' notification
  rules — the multi-recipient counterpart to `maybe_create_from_activity/1`
  for events whose audience is a set (project members, watchers) rather
  than a single `target_uuid`.

  Each recipient is evaluated independently through the SAME machinery
  (prefs, per-channel routing, digest cadences, self-action skip) by
  re-routing a copy of the entry with that recipient as target — WITHOUT
  inserting additional activity rows, so the feed keeps one canonical
  entry while deliveries still key on its committed uuid.

  Returns the per-recipient results in order.
  """
  @spec fan_out_from_activity(Entry.t(), [String.t()]) :: [
          {:ok, Notification.t() | :skipped} | {:error, term()}
        ]
  def fan_out_from_activity(%Entry{} = entry, user_uuids) when is_list(user_uuids) do
    user_uuids
    |> Enum.uniq()
    |> Enum.map(&maybe_create_from_activity(%{entry | target_uuid: &1}))
  end

  # Model B — the in-app inbox and external channels are INDEPENDENT
  # destinations. Create the inbox row iff the user wants it in-app AND in-app is
  # on the "immediate" cadence (a digest cadence skips the per-event row — the
  # DigestWorker posts one summary row later); enqueue external delivery for
  # every channel that wants this type. Loading the user once (the pref check +
  # channel routing both need it) keeps this at a single extra read.
  defp route_activity(%Entry{} = entry) do
    user = Auth.get_user(entry.target_uuid)

    {in_app?, targets} =
      if user do
        {Prefs.user_wants?(user, entry.action) and inapp_immediate?(user, entry.action),
         Routing.targets_for_action(user, entry.action)}
      else
        {Prefs.user_wants?(entry.target_uuid, entry.action), []}
      end

    if in_app? or targets != [] do
      do_create(entry, in_app?, targets)
    else
      {:ok, :skipped}
    end
  end

  # Whether in-app delivery for this action's type is immediate (the default) vs
  # a digest cadence. Cadence lives in the synthetic `"inapp"` channel config;
  # absent ⇒ "immediate" ⇒ the inbox behaves exactly as before.
  defp inapp_immediate?(user, action) do
    case Types.key_for_action(action) do
      nil ->
        true

      type_key ->
        ChannelConfig.cadence(ChannelConfig.for_channel(user, "inapp"), type_key) == "immediate"
    end
  end

  # The inbox row (if wanted) and external delivery are INDEPENDENT: insert the
  # row first and on its own, then enqueue delivery best-effort. The delivery
  # jobs key on the already-committed activity uuid (no inbox row required), and
  # a failing/absent Oban must never roll back or drop the user-visible inbox
  # row — so enqueue is deliberately NOT in the insert's transaction.
  defp do_create(%Entry{} = entry, in_app?, targets) do
    result = if in_app?, do: insert_inbox_row(entry), else: {:ok, :dispatched}
    enqueue_immediate_delivery(entry, targets)
    result
  end

  defp insert_inbox_row(%Entry{} = entry) do
    %Notification{}
    |> Notification.changeset(%{activity_uuid: entry.uuid, recipient_uuid: entry.target_uuid})
    |> repo().insert()
    |> case do
      {:ok, notification} ->
        # Preload activity so subscribers render immediately, no roundtrip.
        notification = %{notification | activity: entry}
        Events.broadcast(entry.target_uuid, {:notification_created, notification})
        {:ok, notification}

      {:error, cs} ->
        handle_insert_error(cs)
    end
  end

  # One idempotent Oban job per {source, channel} for IMMEDIATE-cadence channels
  # (digest cadences are swept by `DigestWorker` on a cron). Best-effort: a
  # delivery-enqueue failure — including Oban not being started — is logged and
  # swallowed so it can never take down the inbox row or crash activity logging.
  defp enqueue_immediate_delivery(%Entry{} = entry, targets) do
    type_key = Types.key_for_action(entry.action)

    base = %{
      "activity_uuid" => entry.uuid,
      "recipient_uuid" => entry.target_uuid,
      "type_key" => type_key
    }

    if is_binary(type_key) do
      for {channel, config} <- targets, ChannelConfig.immediate?(config, type_key) do
        Oban.insert(DeliveryWorker.build(Map.put(base, "channel", channel.key())))
      end
    end

    :ok
  rescue
    e ->
      Logger.warning("Notifications delivery enqueue failed: #{inspect(e)}")
      :ok
  end

  # A duplicate (activity_uuid, recipient_uuid) insert is a no-op, not an error.
  defp handle_insert_error(%Ecto.Changeset{errors: [{_, {_, opts}} | _]} = cs) do
    if Keyword.get(opts, :constraint) == :unique do
      {:ok, :skipped}
    else
      Logger.warning("Notifications insert failed: #{inspect(cs.errors)}")
      {:error, cs}
    end
  end

  defp handle_insert_error(cs) do
    Logger.warning("Notifications insert failed: #{inspect(cs.errors)}")
    {:error, cs}
  end

  @doc """
  Create a **standalone** notification — one not tied to an activity
  (V126). Use for app-driven notices that don't originate from the
  activity log (e.g. "your export is ready").

  `attrs` keys:
    * `:recipient_uuid` (required) — who receives it
    * `:text` / `:icon` / `:link` — convenience, folded into `metadata`
      as `notification_text` / `notification_icon` / `notification_link`
      (the keys `Render` reads)
    * `:metadata` — raw metadata map (merged under the convenience keys)
    * `:type` — optional notification type key (e.g. `"account"`,
      `"posts"`, or a module-contributed type). When given, the send is
      filtered through the recipient's per-type preference
      (`Prefs.user_wants_type?/2`, fail-open).
    * `:action` — optional action string (e.g. `"post.commented"`). When
      given, filtered through `Prefs.user_wants?/2` (which maps the
      action to a type). Use `:type` OR `:action`, not both.

      Notifications.create(%{
        recipient_uuid: user.uuid,
        text: "Your export is ready.",
        icon: "hero-arrow-down-tray",
        link: "/exports/123"
      })

  Honors the global `notifications_enabled` kill-switch. With neither
  `:type` nor `:action`, it's an unconditional app-driven send (no
  preference filtering). Returns `{:ok, %Notification{}}`,
  `{:ok, :skipped}` (disabled or filtered out by prefs), or
  `{:error, changeset}`. Broadcasts `{:notification_created, n}` on success.
  """
  def create(attrs) when is_map(attrs) do
    cond do
      not enabled?() -> {:ok, :skipped}
      not wants_standalone?(attrs) -> {:ok, :skipped}
      true -> do_create_standalone(attrs)
    end
  rescue
    e ->
      Logger.warning("Notifications.create failed: #{inspect(e)}")
      {:ok, :skipped}
  end

  @doc """
  Create a standalone notification for **many** recipients in one call —
  the multi-recipient counterpart to `create/1`. `recipient_uuids` is a
  list; `attrs` is the same shape as `create/1` minus `:recipient_uuid`
  (it's supplied per recipient).

  The recipient list is the caller's responsibility (e.g. the followers
  of an author) — this is the generic fan-out primitive, not an audience
  resolver. Duplicate uuids are de-duped. Each recipient is filtered
  independently through `:type` / `:action` prefs when given, so muted
  users are skipped. Honors the kill-switch once up front.

      Notifications.create_many(follower_uuids, %{
        type: "posts",
        text: "Alice published a new post.",
        link: "/posts/\#{post.id}"
      })

  Returns `{:ok, created_count}` (notifications actually inserted, i.e.
  excluding disabled / pref-skipped) or `{:ok, :skipped}` when
  notifications are globally disabled.
  """
  def create_many(recipient_uuids, attrs) when is_list(recipient_uuids) and is_map(attrs) do
    if enabled?() do
      created =
        recipient_uuids
        |> Enum.uniq()
        |> Enum.count(fn uuid ->
          match?({:ok, %Notification{}}, create(Map.put(attrs, :recipient_uuid, uuid)))
        end)

      {:ok, created}
    else
      {:ok, :skipped}
    end
  end

  @doc """
  Insert an in-app-only notification row directly — used by the DigestWorker to
  post an aggregated in-app summary ("1,432 likes this hour"). Bypasses the
  kill-switch/preference checks (the digest already decided to post) and never
  routes externally. `display` carries `:text` / `:icon` / `:link`.
  """
  @spec create_inapp(String.t(), map()) :: {:ok, Notification.t()} | {:error, term()}
  def create_inapp(recipient_uuid, display) when is_binary(recipient_uuid) and is_map(display) do
    # Caller metadata first, reserved keys on top — the reverse order let a
    # passed-through `metadata` (say, copied off a prior notification)
    # silently clobber the `dedupe_key` the upsert had just decided on,
    # turning collapsing off for that key with nothing logged. A reserved
    # key is only stamped when the caller supplied the display field, so
    # setting `notification_text` via metadata alone still works.
    metadata =
      display[:metadata]
      |> stringify_keys()
      |> put_meta("notification_text", display[:text])
      |> put_meta("notification_icon", display[:icon])
      |> put_meta("notification_link", display[:link])
      # What `upsert_inapp/3` later collapses on. Dropped silently without
      # this.
      |> put_meta("dedupe_key", display[:dedupe_key])

    %Notification{}
    |> Notification.changeset(%{
      recipient_uuid: recipient_uuid,
      activity_uuid: nil,
      metadata: metadata
    })
    |> Ecto.Changeset.unique_constraint(:metadata,
      name: :phoenix_kit_notifications_dedupe_unseen_idx
    )
    |> repo().insert()
    |> case do
      {:ok, notification} ->
        notification = %{notification | activity: nil}
        Events.broadcast(recipient_uuid, {:notification_created, notification})
        {:ok, notification}

      {:error, %Ecto.Changeset{} = cs} ->
        # The dedupe uniqueness trip is an ANTICIPATED outcome — it is how
        # `insert_collapsible/3` learns it lost the race and should fold —
        # so it doesn't warrant a warning; everything else does.
        unless dedupe_conflict?(cs) do
          Logger.warning("Notifications.create_inapp failed: #{inspect(cs.errors)}")
        end

        {:error, cs}
    end
  end

  defp dedupe_conflict?(%Ecto.Changeset{errors: errors}) do
    case Keyword.get(errors, :metadata) do
      {_, opts} -> Keyword.get(opts, :constraint) == :unique
      _ -> false
    end
  end

  @doc """
  Post an in-app notification, or refresh the one already standing for the
  same `key`.

  This is the GitHub-style collapsing entry — "3 new comments on earlier
  chapters" — where a second event should update the row a user has not dealt
  with yet rather than add another beside it.

  Doing that without an API meant reaching past it: querying
  `PhoenixKit.Notifications.Notification` directly, `update_all`-ing the row,
  and then re-broadcasting `:notification_created` by hand, because the only
  broadcast fired on insert. One host that tried it with a schemaless write
  stringified `metadata` into the jsonb column and 500'd that user's bell.

  ## What counts as "already standing"

  An undismissed, **unseen** notification for the same recipient carrying the
  same key. Once someone has read it, the next event is news again and gets
  its own row — collapsing into something already read would hide it, and the
  unseen-first ordering exists precisely so unread work stays visible.

  ## Refreshing

  `display` replaces the text/icon/link, and `inserted_at` moves to now so the
  refreshed entry sorts as new. Any other metadata keys the caller passes are
  merged, leaving keys it doesn't mention alone.

      iex> upsert_inapp(user_uuid, "comments:chapter:42", %{text: "3 new comments"})
      {:ok, %Notification{}}

  Broadcasts either way — `{:notification_created, n}` for a new row,
  `{:notification_updated, n}` for a refresh — so a bell that is already open
  reflects it without the caller broadcasting anything itself.

  Honors the `notifications_enabled` kill switch like `create/1` does,
  returning `{:ok, :skipped}` when notifications are off — this is a
  host-facing entry point, not the digest's private lane, and "off" that
  quietly doesn't apply to the newest creation path isn't off.
  """
  @spec upsert_inapp(String.t(), String.t(), map()) ::
          {:ok, Notification.t()} | {:ok, :skipped} | {:error, term()}
  def upsert_inapp(recipient_uuid, key, display)
      when is_binary(recipient_uuid) and is_binary(key) and is_map(display) do
    if enabled?() do
      case find_collapsible(recipient_uuid, key) do
        nil -> insert_collapsible(recipient_uuid, key, display)
        existing -> refresh_inapp(existing, key, display)
      end
    else
      {:ok, :skipped}
    end
  end

  # Insert a fresh keyed row — with the concurrency backstop. Two concurrent
  # upserts for the same absent key (parallel Oban workers, two nodes) both
  # read nil from `find_collapsible/2`; without the partial unique index
  # (V170) both inserted, and the user got two unseen rows for one logical
  # key. The second insert now trips the constraint, and the loser retries
  # the find — the winner's row is there to collapse onto.
  defp insert_collapsible(recipient_uuid, key, display) do
    case create_inapp(recipient_uuid, Map.put(display, :dedupe_key, key)) do
      {:error, %Ecto.Changeset{errors: errors} = cs} ->
        if Keyword.has_key?(errors, :metadata) do
          case find_collapsible(recipient_uuid, key) do
            nil -> {:error, cs}
            existing -> refresh_inapp(existing, key, display)
          end
        else
          {:error, cs}
        end

      other ->
        other
    end
  end

  # Only unseen rows collapse — see the moduledoc above for why. Newest first
  # (uuid as the tie-break: UUIDv7 is time-ordered below `inserted_at`'s
  # second granularity) so a duplicate key folds into the one the user most
  # recently got.
  defp find_collapsible(recipient_uuid, key) do
    Notification
    |> where([n], n.recipient_uuid == ^recipient_uuid)
    |> where([n], is_nil(n.dismissed_at) and is_nil(n.seen_at))
    |> where([n], fragment("?->>'dedupe_key' = ?", n.metadata, ^key))
    |> order_by([n], desc: n.inserted_at, desc: n.uuid)
    |> limit(1)
    |> repo().one()
  rescue
    # A read that fails is not a reason to drop the notification — fall
    # through and post a new one. Logged so a permanent failure (a query or
    # schema bug turning every call into nil) is diagnosable instead of
    # silently degrading upsert into insert-always.
    error ->
      Logger.warning("Notifications.find_collapsible failed: #{Exception.message(error)}")
      nil
  catch
    # An unreachable DB raises on an unowned checkout but EXITS on a dead
    # pool — the soft-failure rule needs both.
    :exit, reason ->
      Logger.warning("Notifications.find_collapsible exited: #{inspect(reason)}")
      nil
  end

  defp refresh_inapp(%Notification{} = notification, key, display) do
    # Same order as `create_inapp/2`: caller metadata first, reserved keys
    # on top, so a passed-through metadata map cannot clobber them.
    patch =
      display[:metadata]
      |> stringify_keys()
      |> put_meta("notification_text", display[:text])
      |> put_meta("notification_icon", display[:icon])
      |> put_meta("notification_link", display[:link])

    now = UtilsDate.utc_now()

    query =
      from(n in Notification,
        where: n.uuid == ^notification.uuid,
        # The same guards `find_collapsible/2` reads through, repeated in the
        # write. Without them the row count can never be 0 for a row that
        # still exists, so the "dismissed or seen in between" fallback below
        # was unreachable: a row the user dismissed or read after the read and
        # before the write got refreshed anyway, and the event disappeared
        # into a row they had already dealt with — the exact outcome the
        # unseen-only rule exists to prevent.
        where: is_nil(n.dismissed_at) and is_nil(n.seen_at),
        update: [
          set: [
            # Merged, not replaced: the caller is saying what changed, and the
            # dedupe key it collapsed on lives in here too.
            metadata: fragment("COALESCE(?, '{}'::jsonb) || ?", n.metadata, type(^patch, :map)),
            # Moves to now so a refreshed entry sorts as new rather than
            # staying wherever the first event of the run left it.
            inserted_at: ^now
          ]
        ],
        select: n
      )

    case repo().update_all(query, []) do
      {1, [updated]} ->
        updated = %{updated | activity: nil}
        Events.broadcast(updated.recipient_uuid, {:notification_updated, updated})
        {:ok, updated}

      _ ->
        # Dismissed, seen or pruned between the read and the write — post a
        # fresh one rather than losing the event. It has to carry the dedupe
        # key: a replacement row without one never collapses again, so a
        # single lost race would silently turn collapsing off for that key
        # forever.
        create_inapp(notification.recipient_uuid, Map.put(display, :dedupe_key, key))
    end
  end

  # Apply the optional per-recipient preference filter. `:type` checks the
  # type pref directly; `:action` maps the action to a type. With neither,
  # the send is unconditional.
  defp wants_standalone?(%{type: type, recipient_uuid: uuid})
       when is_binary(type) and is_binary(uuid),
       do: Prefs.user_wants_type?(uuid, type)

  defp wants_standalone?(%{action: action, recipient_uuid: uuid})
       when is_binary(action) and is_binary(uuid),
       do: Prefs.user_wants?(uuid, action)

  defp wants_standalone?(_attrs), do: true

  # NOTE: standalone external delivery requires the inbox row (`create/1`'s
  # `wants_standalone?` gate has already passed here) — i.e. standalone
  # notifications are NOT independently routable the way activity-driven ones
  # are. Standalone messages are app-authored one-offs; the per-type
  # "inbox-off, Telegram-on" independence is an activity-driven concern.
  defp do_create_standalone(attrs) do
    metadata =
      (attrs[:metadata] || %{})
      |> put_meta("notification_text", attrs[:text])
      |> put_meta("notification_icon", attrs[:icon])
      |> put_meta("notification_link", attrs[:link])

    recipient = attrs[:recipient_uuid]
    user = recipient && Auth.get_user(recipient)
    targets = standalone_targets(user, attrs)
    type_key = standalone_type_key(attrs)

    changeset =
      Notification.changeset(%Notification{}, %{
        recipient_uuid: recipient,
        activity_uuid: nil,
        metadata: metadata
      })

    # Decoupled like the activity path: the inbox row must never be lost because
    # an external-delivery enqueue hiccuped, so we insert it in its own step and
    # enqueue delivery best-effort afterwards (referencing the now-known uuid).
    case repo().insert(changeset) do
      {:ok, notification} ->
        # No activity for a standalone row — pin it nil so Render takes the
        # metadata path (a freshly-inserted struct otherwise carries a
        # NotLoaded association, which Render's activity clause would choke on).
        notification = %{notification | activity: nil}
        Events.broadcast(notification.recipient_uuid, {:notification_created, notification})
        enqueue_standalone_delivery(targets, notification.uuid, recipient, type_key)
        {:ok, notification}

      {:error, %Ecto.Changeset{} = cs} ->
        Logger.warning("Notifications.create insert failed: #{inspect(cs.errors)}")
        {:error, cs}
    end
  end

  # External channels wanting this standalone notification. Fail-closed: without
  # an explicit `:type` or `:action`, nothing routes externally.
  defp standalone_targets(nil, _attrs), do: []

  defp standalone_targets(user, %{type: type}) when is_binary(type),
    do: Routing.targets_for_type(user, type)

  defp standalone_targets(user, %{action: action}) when is_binary(action),
    do: Routing.targets_for_action(user, action)

  defp standalone_targets(_user, _attrs), do: []

  defp standalone_type_key(%{type: type}) when is_binary(type), do: type

  defp standalone_type_key(%{action: action}) when is_binary(action),
    do: Types.key_for_action(action)

  defp standalone_type_key(_attrs), do: nil

  # Delivery jobs for a standalone row — keyed on the inserted notification uuid,
  # since there's no activity to render from. Best-effort: a failed enqueue must
  # not cost the user the inbox row that already persisted.
  defp enqueue_standalone_delivery([], _uuid, _recipient, _type_key), do: :ok

  defp enqueue_standalone_delivery(targets, notification_uuid, recipient, type_key) do
    for {channel, _config} <- targets do
      Oban.insert(
        DeliveryWorker.build(%{
          "notification_uuid" => notification_uuid,
          "recipient_uuid" => recipient,
          "type_key" => type_key,
          "channel" => channel.key()
        })
      )
    end

    :ok
  rescue
    e ->
      Logger.warning("Notifications standalone delivery enqueue failed: #{inspect(e)}")
      :ok
  end

  defp put_meta(meta, _key, nil), do: meta
  defp put_meta(meta, _key, ""), do: meta
  defp put_meta(meta, key, val), do: Map.put(meta, key, val)

  # Caller metadata arrives with whatever keys the caller typed —
  # `%{notification_text: ...}` and `%{"notification_text" => ...}` are the
  # same key once serialized to jsonb, but as an Elixir map they coexist and
  # which one wins the JSON encoding is adapter-order-dependent. Normalized
  # here so the reserved-key stamping above has one namespace to win in.
  defp stringify_keys(nil), do: %{}

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_string(k), v} end)
  end

  # ── Reads ────────────────────────────────────────────────────────────

  @doc """
  Returns `{notifications, total_count}` for the given user — unseen first,
  then newest first within each group.

  Options:
    * `:page` (default 1) / `:per_page` (default 25)
    * `:status` — `:unread` (seen_at nil) | `:all` (default)
    * `:dismissed` — `:exclude` (default, active only) | `:only` (the dismissed
      "trash" view) | `:include` (both). The legacy `:include_dismissed` bool is
      still honored (`true` ⇒ `:include`).
  """
  def list_for_user(user_uuid, opts \\ []) when is_binary(user_uuid) do
    page = Keyword.get(opts, :page, 1)
    per_page = Keyword.get(opts, :per_page, 25)
    status = Keyword.get(opts, :status, :all)

    base_query =
      Notification
      |> where([n], n.recipient_uuid == ^user_uuid)
      |> filter_dismissed(dismissed_filter(opts))
      |> maybe_filter_unread(status)

    total = repo().aggregate(base_query, :count, :uuid)

    rows =
      base_query
      |> order_unseen_first()
      |> limit(^per_page)
      |> offset(^((page - 1) * per_page))
      |> repo().all()
      |> repo().preload(activity: [:actor])

    {rows, total}
  end

  # Unseen first, then newest first inside each group.
  #
  # Newest-first alone interleaves the two: read one notification and it stays
  # where it was, so anything you haven't looked at yet ends up scattered among
  # things you have. On an inbox of any size that means scrolling the whole
  # list to find what you missed — the one question a notification centre
  # exists to answer at a glance.
  #
  # Ordering by seen-ness pulls everything outstanding to the top and keeps it
  # there until you deal with it, which is also why "seen" is only ever set by
  # an explicit action: nothing moves while you are looking at it.
  #
  # `IS NOT NULL` rather than `is_nil(...)` inverted, because false sorts
  # before true — so unseen (NULL `seen_at`, hence false) comes first without
  # a negation to read past.
  #
  # `uuid` last makes the order total. `inserted_at` is `:utc_datetime`, so
  # everything fanned out inside the same second ties, and a tie under
  # LIMIT/OFFSET lets Postgres return a row on two pages or on neither. The
  # keys are UUIDv7, which is time-ordered, so descending on it agrees with
  # newest-first instead of scrambling the tied block.
  defp order_unseen_first(query) do
    order_by(query, [n],
      asc: fragment("? IS NOT NULL", n.seen_at),
      desc: n.inserted_at,
      desc: n.uuid
    )
  end

  @doc """
  Returns `{notifications, total_count}` across ALL users, newest first, for the
  admin overview. Recipient and activity(+actor) are preloaded so the admin
  table can show who each notification is for and what it's about.

  Deliberately plain newest-first, unlike the per-user reads: "seen" belongs to
  the recipient, and an admin scanning everybody's notifications is reading a
  chronological record, not working through their own inbox. Sorting a shared
  audit feed by whether somebody else has read each row would reorder it
  differently for no one's benefit.

  Options: `:page` (default 1) / `:per_page` (default 25).
  """
  def admin_list(opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = Keyword.get(opts, :per_page, 25)

    total = repo().aggregate(Notification, :count, :uuid)

    rows =
      Notification
      # `uuid` breaks second-granularity `inserted_at` ties so this offset
      # paging is stable — see `order_unseen_first/1`. The seen-ness key is
      # deliberately absent, per the note above.
      |> order_by([n], desc: n.inserted_at, desc: n.uuid)
      |> limit(^per_page)
      |> offset(^((page - 1) * per_page))
      |> repo().all()
      |> repo().preload([:recipient, activity: [:actor]])

    {rows, total}
  rescue
    _ -> {[], 0}
  end

  @doc """
  Returns the N most-recent undismissed notifications for a user, unseen
  first.

  Drives the bell dropdown. Activity (and actor) are preloaded.

  Unseen first matters more here than in the full list: the dropdown shows a
  handful, so with a plain newest-first order a notification you had already
  read could push an unread one off the bottom entirely — the badge counts it,
  and opening the bell doesn't show it.
  """
  def recent_for_user(user_uuid, limit \\ 10) when is_binary(user_uuid) do
    Notification
    |> where([n], n.recipient_uuid == ^user_uuid and is_nil(n.dismissed_at))
    |> order_unseen_first()
    |> limit(^limit)
    |> repo().all()
    |> repo().preload(activity: [:actor])
  end

  @doc "Counts undismissed, unseen notifications for a user. Drives the badge."
  def count_unread(user_uuid) when is_binary(user_uuid) do
    Notification
    |> where(
      [n],
      n.recipient_uuid == ^user_uuid and is_nil(n.seen_at) and is_nil(n.dismissed_at)
    )
    |> repo().aggregate(:count, :uuid)
  rescue
    _ -> 0
  end

  @doc "Fetches one notification scoped to the recipient. Returns `nil` if missing."
  def get_notification(user_uuid, uuid) when is_binary(user_uuid) and is_binary(uuid) do
    Notification
    |> where([n], n.uuid == ^uuid and n.recipient_uuid == ^user_uuid)
    |> repo().one()
    |> maybe_preload()
  end

  defp maybe_preload(nil), do: nil
  defp maybe_preload(%Notification{} = n), do: repo().preload(n, activity: [:actor])

  # ── State transitions ────────────────────────────────────────────────

  @doc """
  Marks a single notification as seen. Idempotent — already-seen rows return
  `{:ok, notification}` unchanged.
  """
  def mark_seen(user_uuid, uuid) when is_binary(user_uuid) and is_binary(uuid) do
    case get_notification(user_uuid, uuid) do
      nil ->
        {:error, :not_found}

      %Notification{seen_at: %DateTime{}} = notification ->
        {:ok, notification}

      %Notification{} = notification ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        notification
        |> Ecto.Changeset.change(seen_at: now)
        |> repo().update()
        |> broadcast_state(user_uuid, :notification_seen)
    end
  end

  @doc "Bulk-marks all unseen notifications as seen. Returns `{count, nil}`."
  def mark_all_seen(user_uuid) when is_binary(user_uuid) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      Notification
      |> where([n], n.recipient_uuid == ^user_uuid and is_nil(n.seen_at))
      |> repo().update_all(set: [seen_at: now])

    # A bulk-level broadcast lets subscribers refetch; per-row broadcasts would
    # be chatty at scale.
    Events.broadcast(user_uuid, {:notifications_bulk_updated, :seen})
    {count, nil}
  end

  @doc "Dismisses a single notification, also marking it read. Idempotent."
  def dismiss(user_uuid, uuid) when is_binary(user_uuid) and is_binary(uuid) do
    case get_notification(user_uuid, uuid) do
      nil ->
        {:error, :not_found}

      %Notification{dismissed_at: %DateTime{}} = notification ->
        {:ok, notification}

      %Notification{} = notification ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        # Dismiss implies "handled", so also clear the unread flag (preserving an
        # existing seen_at). Keeps the unread badge accurate, avoids bold rows in
        # the Dismissed list, and Restore brings the item back as read.
        notification
        |> Ecto.Changeset.change(dismissed_at: now, seen_at: notification.seen_at || now)
        |> repo().update()
        |> broadcast_state(user_uuid, :notification_dismissed)
    end
  end

  @doc "Restores (un-dismisses) a single notification. Idempotent."
  def restore(user_uuid, uuid) when is_binary(user_uuid) and is_binary(uuid) do
    case get_notification(user_uuid, uuid) do
      nil ->
        {:error, :not_found}

      %Notification{dismissed_at: nil} = notification ->
        {:ok, notification}

      %Notification{} = notification ->
        notification
        |> Ecto.Changeset.change(dismissed_at: nil)
        |> repo().update()
        # Reuses the dismissed-state-change event — consumers (bell, inbox) just
        # reload, so a restored notification reappears in the active list/bell.
        |> broadcast_state(user_uuid, :notification_dismissed)
    end
  end

  @doc "Bulk-dismisses all undismissed notifications, also marking them read. Returns `{count, nil}`."
  def dismiss_all(user_uuid) when is_binary(user_uuid) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    # Also clear the unread flag on dismiss (COALESCE preserves an existing
    # seen_at), matching dismiss/2.
    {count, _} =
      Notification
      |> where([n], n.recipient_uuid == ^user_uuid and is_nil(n.dismissed_at))
      |> update([n],
        set: [dismissed_at: ^now, seen_at: fragment("COALESCE(?, ?)", n.seen_at, ^now)]
      )
      |> repo().update_all([])

    Events.broadcast(user_uuid, {:notifications_bulk_updated, :dismissed})
    {count, nil}
  end

  # ── Retention / pruning ─────────────────────────────────────────────

  @doc "Deletes notifications whose underlying activity is older than `days`."
  def prune(days) when is_integer(days) and days > 0 do
    cutoff = DateTime.add(DateTime.utc_now(), -days * 86_400, :second)

    {count, _} =
      from(n in Notification,
        join: e in Entry,
        on: e.uuid == n.activity_uuid,
        where: e.inserted_at < ^cutoff
      )
      |> repo().delete_all()

    Logger.info("Pruned #{count} notifications older than #{days} days")
    {:ok, count}
  end

  @doc "Retention period in days. Falls back to activity retention if unset."
  def retention_days do
    case Settings.get_setting("notifications_retention_days", nil) do
      val when is_binary(val) ->
        case Integer.parse(val) do
          {n, _} when n > 0 -> n
          _ -> fallback_retention()
        end

      _ ->
        fallback_retention()
    end
  rescue
    _ -> fallback_retention()
  end

  defp fallback_retention do
    # Match activity retention when the notifications-specific setting is unset —
    # we never want to outlive the activity we reference (it's cascaded anyway).
    PhoenixKit.Activity.retention_days()
  end

  # ── Module behaviour (toggleable module on the admin Modules page) ────

  @impl PhoenixKit.Module
  def module_key, do: "notifications"

  @impl PhoenixKit.Module
  def module_name, do: "Notifications"

  @impl PhoenixKit.Module
  def enable_system, do: Settings.update_boolean_setting("notifications_enabled", true)

  @impl PhoenixKit.Module
  def disable_system, do: Settings.update_boolean_setting("notifications_enabled", false)

  @impl PhoenixKit.Module
  def get_config do
    # Called for every module on each /admin/modules render. Skip the
    # count query entirely when disabled — the stats aren't shown then.
    if enabled?() do
      Map.merge(%{enabled: true}, admin_stats())
    else
      %{enabled: false}
    end
  end

  @impl PhoenixKit.Module
  def permission_metadata do
    %{
      key: "notifications",
      label: "Notifications",
      icon: "hero-bell",
      description:
        "Administer other users' notifications (personal inbox and preferences need no grant)"
    }
  end

  @impl PhoenixKit.Module
  def admin_tabs do
    [
      # These three are PERSONAL pages — a user's own inbox and their own
      # per-type preferences — so they carry no `permission:`. Notifications are
      # delivered to every user, and requiring a grant to read your own meant an
      # account could receive mail it was structurally unable to open, while the
      # bell's "View all" pointed at a tab the sidebar was hiding.
      #
      # `visible:` carries the kill switch that `permission:` used to carry for
      # free — the registry only consults module-enabled state for tabs that
      # name a permission key.
      #
      # The `notifications` key is not vestigial: it is reserved for an
      # all-users/moderation view, which is an administrative capability.
      Tab.new!(
        id: :admin_notifications,
        label: "Notifications",
        icon: "hero-bell",
        path: "notifications",
        priority: 640,
        level: :admin,
        personal: true,
        visible: fn _scope -> __MODULE__.enabled?() end,
        match: :prefix,
        group: :admin_modules,
        subtab_display: :when_active,
        highlight_with_subtabs: false,
        gettext_backend: PhoenixKitWeb.Gettext
      ),
      # My Notifications shares the parent path. Exact-only regex so it stays
      # lit on the bare inbox URL and does NOT prefix-match /settings
      # (mirrors the :admin_users_manage precedent in AdminTabs).
      Tab.new!(
        id: :admin_notifications_mine,
        label: "My Notifications",
        icon: "hero-inbox",
        path: "notifications",
        priority: 641,
        level: :admin,
        personal: true,
        visible: fn _scope -> __MODULE__.enabled?() end,
        parent: :admin_notifications,
        match: {:regex, ~r{^/admin/notifications$}},
        gettext_backend: PhoenixKitWeb.Gettext
      ),
      Tab.new!(
        id: :admin_notifications_settings,
        label: "My Settings",
        icon: "hero-adjustments-horizontal",
        path: "notifications/settings",
        priority: 642,
        level: :admin,
        personal: true,
        visible: fn _scope -> __MODULE__.enabled?() end,
        parent: :admin_notifications,
        match: :prefix,
        gettext_backend: PhoenixKitWeb.Gettext
      )
    ]
  end

  @doc """
  Aggregate counts for the admin overview page: total notifications,
  `unread` (neither seen nor dismissed), and `dismissed`. A single
  `count(...) FILTER (WHERE ...)` query — one table scan, not three.
  Rescues to zeros so the page never crashes on a query hiccup.
  """
  def admin_stats do
    Notification
    |> select([n], %{
      total: count(n.uuid),
      unread: filter(count(n.uuid), is_nil(n.seen_at) and is_nil(n.dismissed_at)),
      dismissed: filter(count(n.uuid), not is_nil(n.dismissed_at))
    })
    |> repo().one()
  rescue
    _ -> %{total: 0, unread: 0, dismissed: 0}
  end

  # ── Settings ─────────────────────────────────────────────────────────

  @doc "Is the notifications feature enabled? Default `true`."
  @impl PhoenixKit.Module
  def enabled? do
    # Deliberately the uncached read: this is the kill-switch, and the
    # `:settings` cache is node-local with no cross-node invalidation or TTL
    # (see PhoenixKit.Cache) — a cached read would let a disable on one node
    # go unseen on others until restart. An always-fresh read keeps the
    # switch cluster-wide and immediate.
    case Settings.get_setting("notifications_enabled", "true") do
      "false" -> false
      false -> false
      _ -> true
    end
  rescue
    _ -> true
  end

  # ── Internals ────────────────────────────────────────────────────────

  # Resolve the dismissed-row filter. The explicit `:dismissed` opt wins; falls
  # back to the legacy `:include_dismissed` bool for callers not yet updated.
  defp dismissed_filter(opts) do
    case Keyword.get(opts, :dismissed) do
      nil -> if Keyword.get(opts, :include_dismissed, false), do: :include, else: :exclude
      value -> value
    end
  end

  defp filter_dismissed(query, :include), do: query
  defp filter_dismissed(query, :only), do: where(query, [n], not is_nil(n.dismissed_at))
  defp filter_dismissed(query, _exclude), do: where(query, [n], is_nil(n.dismissed_at))

  defp maybe_filter_unread(query, :unread), do: where(query, [n], is_nil(n.seen_at))
  defp maybe_filter_unread(query, _), do: query

  defp broadcast_state({:ok, notification}, user_uuid, event) do
    notification = repo().preload(notification, activity: [:actor])
    Events.broadcast(user_uuid, {event, notification})
    {:ok, notification}
  end

  defp broadcast_state({:error, _} = err, _user_uuid, _event), do: err

  defp repo do
    PhoenixKit.RepoHelper.repo()
  end
end
