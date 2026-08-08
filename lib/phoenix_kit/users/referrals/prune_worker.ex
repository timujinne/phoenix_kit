defmodule PhoenixKit.Users.Referrals.PruneWorker do
  @moduledoc """
  Oban worker that deactivates accounts which were created under invite-only
  and never satisfied it.

  **Off unless asked for.** `referral_unadmitted_retention_days` defaults to
  `0`, which means never — so an operator who switches invite-only on does not
  silently acquire a job that deactivates their users. Set it to a positive
  number of days to turn the janitor on.

  Deactivates; never deletes. See `PhoenixKit.Users.Referrals.prune_unadmitted/1`
  for the exemptions it re-checks per account.

  Runs daily (wired from `lib/phoenix_kit/install/oban_config.ex`).
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3

  require Logger

  alias PhoenixKit.Users.Referrals

  @impl Oban.Worker
  def perform(_job) do
    {:ok, count} = Referrals.prune_unadmitted(Referrals.unadmitted_retention_days())

    if count > 0 do
      Logger.info("[Referrals] deactivated #{count} account(s) that never satisfied invite-only")
    end

    :ok
  end
end
