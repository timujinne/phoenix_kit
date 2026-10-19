defmodule PhoenixKit.API.Approvals.Notifier do
  @moduledoc """
  The "approval waiting" notice: when an approval is queued, those who may
  decide it get an in-app notification, **at most one per API key per ten minutes**,
  and an unread one is refreshed instead of repeated.

  The ten-minute window is the `notified_at` column: under a per-key advisory lock the
  first approval of a key to find no `notified_at` in the last ten minutes sets its own
  and sends; the others send nothing. The notification itself goes through
  `PhoenixKit.Notifications.upsert_inapp/3` with the dedupe key
  `api:approvals:<key uuid>`, so a notice nobody has read yet is updated ("3 operations
  are waiting") and a second bell is never added.

  The text is English: a notification row stores its text.
  """

  import Ecto.Query, warn: false
  require Logger

  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.LogSafe
  alias PhoenixKit.Notifications
  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Utils.Routes

  @window_seconds 600

  @doc """
  Tells the deciders of `approval` that it is waiting, unless the key was announced in
  the last ten minutes. Never raises: a failed notice must not fail the API call.
  """
  @spec notify_requested(Confirmation.t(), DateTime.t()) :: :ok | :throttled
  def notify_requested(%Confirmation{} = approval, now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)

    if claim_notice(approval, now) do
      send_notices(approval, now)
      :ok
    else
      :throttled
    end
  rescue
    error ->
      Logger.warning("[PhoenixKit.API] approval notice failed: #{LogSafe.exception_label(error)}")
      :ok
  catch
    :exit, reason ->
      Logger.warning("[PhoenixKit.API] approval notice failed: #{LogSafe.shape(reason)}")
      :ok
  end

  defp claim_notice(%Confirmation{uuid: uuid, actor_key_uuid: key_uuid}, now) do
    cutoff = DateTime.add(now, -@window_seconds, :second)

    {:ok, claimed?} =
      repo().transaction(fn ->
        repo().query!("SELECT pg_advisory_xact_lock(hashtext($1))", [
          "api_approval_notice:" <> key_uuid
        ])

        recent? =
          repo().exists?(
            from(c in Confirmation,
              where:
                c.actor_key_uuid == ^key_uuid and c.kind == "approval" and c.notified_at > ^cutoff
            )
          )

        if recent? do
          false
        else
          repo().update_all(from(c in Confirmation, where: c.uuid == ^uuid),
            set: [notified_at: now]
          )

          true
        end
      end)

    claimed?
  end

  defp send_notices(%Confirmation{actor_key_uuid: key_uuid} = approval, now) do
    key = Keys.get_key(key_uuid)
    waiting = waiting_count(key_uuid, now)

    for user <- Approvals.deciders(approval, key) do
      Notifications.upsert_inapp(user.uuid, "api:approvals:" <> key_uuid, %{
        text: text(key, waiting),
        icon: "hero-shield-check",
        link: Routes.path("/admin/approvals") <> "#approval-" <> approval.uuid
      })
    end

    :ok
  end

  defp waiting_count(key_uuid, now) do
    repo().aggregate(
      from(c in Confirmation,
        where:
          c.actor_key_uuid == ^key_uuid and c.kind == "approval" and c.status == "pending" and
            c.expires_at > ^now
      ),
      :count
    )
  end

  defp text(key, 1),
    do: ~s(1 operation of the API key "#{name(key)}" is waiting for your approval.)

  defp text(key, count),
    do: ~s(#{count} operations of the API key "#{name(key)}" are waiting for your approval.)

  defp name(nil), do: "?"
  defp name(key), do: key.name

  defp repo, do: RepoHelper.repo()
end
