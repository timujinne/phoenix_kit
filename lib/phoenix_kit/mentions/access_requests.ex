defmodule PhoenixKit.Mentions.AccessRequests do
  @moduledoc """
  Asking to be let in to a record you were pointed at but cannot open.

  A redacted mention says "there is something here you can't see". That is
  only worth showing if there is a next step, and this is the next step: the
  reader asks, the people who own the record decide.

  Delivery reuses the activity → notification bridge, so a request arrives
  wherever the recipient already reads things — inbox, email, Telegram —
  with no new plumbing. Deciding is deliberately NOT automated: granting
  access means writing to whatever the owning module calls membership, and
  core has no business guessing that. The module handles the decision and
  calls `grant/2` or `deny/2` to close the loop.
  """

  import Ecto.Query

  require Logger

  alias PhoenixKit.Activity
  alias PhoenixKit.Mentions.AccessRequest
  alias PhoenixKit.RepoHelper
  alias PhoenixKit.ResourceLinks
  alias PhoenixKit.Users.RateLimiter

  # Free-form on the wire; keep it short enough that a forged type cannot
  # bloat the activity row / admin queue listing.
  @max_resource_type_bytes 100

  defp repo, do: RepoHelper.repo()

  @doc """
  Records a request, or returns the one already open.

  Asking twice is the same ask — the partial unique index enforces it, and
  this returns `{:ok, existing}` rather than an error so the UI can say "already
  asked" without a special case.

  Rejects unknown `resource_type`s, non-uuid targets, and accounts that have
  already submitted too many requests in the window — the chip only ever
  sends a type the renderer already resolved, so anything else is a client
  composing its own payload.
  """
  @spec request(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, AccessRequest.t()} | {:error, term()}
  def request(resource_type, resource_uuid, requester_uuid, opts \\ []) do
    with :ok <- validate_target(resource_type, resource_uuid),
         :ok <- RateLimiter.check_access_request_rate_limit(requester_uuid) do
      attrs = %{
        resource_type: resource_type,
        resource_uuid: resource_uuid,
        requester_uuid: requester_uuid,
        source_type: Keyword.get(opts, :source_type),
        source_uuid: Keyword.get(opts, :source_uuid),
        note: Keyword.get(opts, :note)
      }

      %AccessRequest{}
      |> AccessRequest.changeset(attrs)
      |> repo().insert()
      |> case do
        {:ok, request} ->
          notify_deciders(request, opts)
          {:ok, request}

        {:error, changeset} ->
          # The open-request index tripped: they already asked. Hand back the
          # existing row so the caller can report state rather than failure.
          case get_open(resource_type, resource_uuid, requester_uuid) do
            %AccessRequest{} = existing -> {:ok, existing}
            nil -> {:error, changeset}
          end
      end
    end
  end

  defp validate_target(resource_type, resource_uuid) do
    cond do
      not is_binary(resource_type) or resource_type == "" ->
        {:error, :invalid_resource}

      byte_size(resource_type) > @max_resource_type_bytes ->
        {:error, :invalid_resource}

      not known_resource_type?(resource_type) ->
        {:error, :unknown_resource_type}

      match?(:error, Ecto.UUID.cast(resource_uuid)) ->
        {:error, :invalid_resource}

      true ->
        :ok
    end
  end

  # Only types a module has registered (plus core's built-ins on the same
  # map). A free-text type would still insert and Activity.log, which is how
  # an unauthenticated-looking spam path becomes a real write.
  defp known_resource_type?(type) do
    Map.has_key?(ResourceLinks.handlers(), type)
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  @doc "The open request from this person for this record, if any."
  @spec get_open(String.t(), String.t(), String.t()) :: AccessRequest.t() | nil
  def get_open(resource_type, resource_uuid, requester_uuid) do
    from(r in AccessRequest,
      where:
        r.resource_type == ^resource_type and r.resource_uuid == ^resource_uuid and
          r.requester_uuid == ^requester_uuid and r.status == "pending"
    )
    |> repo().one()
  rescue
    _ -> nil
  end

  @doc "Open requests for a record — the owner's queue."
  @spec list_pending(String.t(), String.t()) :: [AccessRequest.t()]
  def list_pending(resource_type, resource_uuid) do
    from(r in AccessRequest,
      where:
        r.resource_type == ^resource_type and r.resource_uuid == ^resource_uuid and
          r.status == "pending",
      order_by: [asc: r.inserted_at]
    )
    |> repo().all()
  rescue
    _ -> []
  end

  @doc "Every open request across all records — the admin queue."
  @spec list_all_pending(keyword()) :: [AccessRequest.t()]
  def list_all_pending(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(r in AccessRequest,
      where: r.status == "pending",
      order_by: [desc: r.inserted_at],
      limit: ^limit
    )
    |> repo().all()
  rescue
    _ -> []
  end

  @doc """
  Closes a request as granted.

  Does NOT itself give anyone access: the owning module knows what its own
  membership means and does that part. This records the decision and tells
  the requester.
  """
  @spec grant(AccessRequest.t(), String.t() | nil) :: {:ok, AccessRequest.t()} | {:error, term()}
  def grant(request, decided_by_uuid), do: decide(request, "granted", decided_by_uuid)

  @doc "Closes a request as denied, and tells the requester."
  @spec deny(AccessRequest.t(), String.t() | nil) :: {:ok, AccessRequest.t()} | {:error, term()}
  def deny(request, decided_by_uuid), do: decide(request, "denied", decided_by_uuid)

  @doc "The requester withdrawing their own ask."
  @spec cancel(AccessRequest.t()) :: {:ok, AccessRequest.t()} | {:error, term()}
  def cancel(request), do: decide(request, "cancelled", nil, notify: false)

  defp decide(request, status, decided_by_uuid, opts \\ []) do
    request
    |> AccessRequest.changeset(%{
      status: status,
      decided_by_uuid: decided_by_uuid,
      decided_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
    |> repo().update()
    |> case do
      {:ok, updated} ->
        if Keyword.get(opts, :notify, true), do: notify_requester(updated)
        {:ok, updated}

      other ->
        other
    end
  end

  # Who decides is the owning module's business. Until a module says
  # otherwise the request is logged with no target, which puts it in the
  # activity feed and the admin queue without pretending to know an owner.
  defp notify_deciders(request, opts) do
    Activity.log(%{
      action: "access_request.created",
      module: "mentions",
      mode: "manual",
      actor_uuid: request.requester_uuid,
      resource_type: request.resource_type,
      resource_uuid: request.resource_uuid,
      target_uuid: Keyword.get(opts, :notify_uuid),
      metadata: %{
        "notification_text" => "Someone asked for access to a record you own",
        "request_uuid" => request.uuid
      }
    })
  rescue
    e -> Logger.warning("[AccessRequests] notify failed: #{Exception.message(e)}")
  catch
    :exit, _ -> :ok
  end

  defp notify_requester(request) do
    Activity.log(%{
      action: "access_request.#{request.status}",
      module: "mentions",
      mode: "manual",
      actor_uuid: request.decided_by_uuid,
      resource_type: request.resource_type,
      resource_uuid: request.resource_uuid,
      target_uuid: request.requester_uuid,
      metadata: %{
        "notification_text" => "Your access request was #{request.status}",
        "request_uuid" => request.uuid
      }
    })
  rescue
    e -> Logger.warning("[AccessRequests] notify failed: #{Exception.message(e)}")
  catch
    :exit, _ -> :ok
  end
end
