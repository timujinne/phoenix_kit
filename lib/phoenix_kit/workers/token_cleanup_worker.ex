defmodule PhoenixKit.Workers.TokenCleanupWorker do
  @moduledoc """
  Oban worker for cleaning up expired authentication tokens.

  This worker runs periodically to remove expired tokens from the database:
  - Password reset tokens (expired after 1 day)
  - Email confirmation tokens (expired after 7 days)
  - Magic link tokens (expired after 15 minutes)
  - Old session tokens (expired after 60 days)

  ## Scheduling

  This worker is scheduled via Oban cron in config/config.exs:

      config :phoenix_kit, Oban,
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             # Clean up expired tokens daily at 2 AM
             {"0 2 * * *", PhoenixKit.Workers.TokenCleanupWorker}
           ]}
        ]

  ## Manual Execution

  You can manually trigger cleanup in development/testing:

      PhoenixKit.Workers.TokenCleanupWorker.perform(%{})

  Or via Oban:

      %{} |> PhoenixKit.Workers.TokenCleanupWorker.new() |> Oban.insert()

  ## Database Impact

  This worker performs DELETE operations with WHERE clauses on indexed columns,
  so it should have minimal performance impact. Expected execution time:
  - Small databases (< 10k tokens): < 100ms
  - Medium databases (10k-100k tokens): < 1s
  - Large databases (> 100k tokens): 1-5s

  ## Monitoring

  All cleanup operations are logged with counts for monitoring:

      [info] Token cleanup completed: deleted 523 expired tokens
             (password_reset: 12, magic_link: 456, session: 55)
  """
  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    priority: 3

  require Logger

  import Ecto.Query

  alias PhoenixKit.RepoHelper, as: Repo
  alias PhoenixKit.Users.Auth.UserToken

  # Token expiry configurations (must match UserToken module)
  @reset_password_validity_in_days 1
  @confirm_validity_in_days 7
  @change_email_validity_in_days 7
  @session_validity_in_days 60
  @magic_link_validity_in_minutes 15

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Starting token cleanup job")

    start_time = System.monotonic_time(:millisecond)

    # Clean up each token type
    counts = %{
      password_reset: cleanup_password_reset_tokens(),
      email_confirmation: cleanup_email_confirmation_tokens(),
      email_change: cleanup_email_change_tokens(),
      magic_link: cleanup_magic_link_tokens(),
      old_sessions: cleanup_old_session_tokens()
    }

    total_deleted = Enum.sum(Map.values(counts))
    duration = System.monotonic_time(:millisecond) - start_time

    Logger.info("Token cleanup completed",
      total_deleted: total_deleted,
      duration_ms: duration,
      password_reset: counts.password_reset,
      email_confirmation: counts.email_confirmation,
      email_change: counts.email_change,
      magic_link: counts.magic_link,
      old_sessions: counts.old_sessions
    )

    :ok
  end

  @doc """
  Clean up expired password reset tokens.

  Returns the number of tokens deleted.
  """
  def cleanup_password_reset_tokens do
    expiry_date = DateTime.utc_now() |> DateTime.add(-@reset_password_validity_in_days, :day)

    query =
      from t in UserToken,
        where:
          t.context == "reset_password" and
            t.inserted_at < ^expiry_date

    {count, _} = Repo.delete_all(query)
    count
  end

  @doc """
  Clean up expired email confirmation tokens.

  Returns the number of tokens deleted.
  """
  def cleanup_email_confirmation_tokens do
    expiry_date = DateTime.utc_now() |> DateTime.add(-@confirm_validity_in_days, :day)

    query =
      from t in UserToken,
        where:
          t.context == "confirm" and
            t.inserted_at < ^expiry_date

    {count, _} = Repo.delete_all(query)
    count
  end

  @doc """
  Clean up expired email change tokens.

  Returns the number of tokens deleted.
  """
  def cleanup_email_change_tokens do
    expiry_date = DateTime.utc_now() |> DateTime.add(-@change_email_validity_in_days, :day)

    query =
      from t in UserToken,
        where:
          fragment("? LIKE 'change:%'", t.context) and
            t.inserted_at < ^expiry_date

    {count, _} = Repo.delete_all(query)
    count
  end

  @doc """
  Clean up expired magic link tokens.

  Magic links have a short expiry (15 minutes by default).

  Returns the number of tokens deleted.
  """
  def cleanup_magic_link_tokens do
    expiry_time =
      DateTime.utc_now() |> DateTime.add(-@magic_link_validity_in_minutes, :minute)

    query =
      from t in UserToken,
        where:
          t.context == "magic_link" and
            t.inserted_at < ^expiry_time

    {count, _} = Repo.delete_all(query)
    count
  end

  @doc """
  Clean up very old session tokens.

  This removes session tokens that are beyond the validity period,
  which helps keep the database clean without affecting active sessions.

  Returns the number of tokens deleted.
  """
  def cleanup_old_session_tokens do
    expiry_date = DateTime.utc_now() |> DateTime.add(-@session_validity_in_days, :day)

    query =
      from t in UserToken,
        where:
          t.context == "session" and
            t.inserted_at < ^expiry_date

    {count, _} = Repo.delete_all(query)
    count
  end

  @doc """
  Get statistics about current tokens in the database.

  Useful for monitoring and capacity planning.

  Returns a map with counts for each token type.

  ## Examples

      iex> PhoenixKit.Workers.TokenCleanupWorker.get_token_stats()
      %{
        total: 1523,
        password_reset: 45,
        email_confirmation: 234,
        email_change: 12,
        magic_link: 67,
        session: 1165,
        expired: 123
      }
  """
  def get_token_stats do
    now = DateTime.utc_now()

    # Calculate expiry dates
    password_reset_expiry = DateTime.add(now, -@reset_password_validity_in_days, :day)
    confirm_expiry = DateTime.add(now, -@confirm_validity_in_days, :day)
    email_change_expiry = DateTime.add(now, -@change_email_validity_in_days, :day)
    magic_link_expiry = DateTime.add(now, -@magic_link_validity_in_minutes, :minute)
    session_expiry = DateTime.add(now, -@session_validity_in_days, :day)

    # Count tokens by type
    password_reset_count =
      Repo.aggregate(
        from(t in UserToken, where: t.context == "reset_password"),
        :count
      )

    confirmation_count =
      Repo.aggregate(
        from(t in UserToken, where: t.context == "confirm"),
        :count
      )

    email_change_count =
      Repo.aggregate(
        from(t in UserToken, where: fragment("? LIKE 'change:%'", t.context)),
        :count
      )

    magic_link_count =
      Repo.aggregate(
        from(t in UserToken, where: t.context == "magic_link"),
        :count
      )

    session_count =
      Repo.aggregate(
        from(t in UserToken, where: t.context == "session"),
        :count
      )

    # Count expired tokens
    expired_count =
      Repo.aggregate(
        from(t in UserToken,
          where:
            (t.context == "reset_password" and t.inserted_at < ^password_reset_expiry) or
              (t.context == "confirm" and t.inserted_at < ^confirm_expiry) or
              (fragment("? LIKE 'change:%'", t.context) and t.inserted_at < ^email_change_expiry) or
              (t.context == "magic_link" and t.inserted_at < ^magic_link_expiry) or
              (t.context == "session" and t.inserted_at < ^session_expiry)
        ),
        :count
      )

    total_count = Repo.aggregate(UserToken, :count)

    %{
      total: total_count,
      password_reset: password_reset_count,
      email_confirmation: confirmation_count,
      email_change: email_change_count,
      magic_link: magic_link_count,
      session: session_count,
      expired: expired_count
    }
  end
end
