defmodule PhoenixKit.Install.Deprecations do
  @moduledoc """
  Advisory deprecation notices surfaced by the installer tasks.

  `mix phoenix_kit.install` and `mix phoenix_kit.update` print these so a host
  learns about upcoming changes while running a task they already run. Nothing
  here changes host code or behaviour — the deprecated features keep working
  exactly as before until they are actually removed in a later release.

  Keeping the wording in one place means the install and update tasks can't
  drift, and gives a single home to escalate a notice (or drop it) as a
  deprecation moves through its lifecycle.
  """

  @doc """
  Heads-up for a host that has **explicitly turned the user dashboard back on**.

  Only worth printing when `PhoenixKit.Config.user_dashboard_enabled?/0` is
  true: since the dashboard stopped being routed by default, silence is the
  correct output for everybody else. Advisory only — the routes still work.
  """
  @spec user_dashboard_warning() :: String.t()
  def user_dashboard_warning do
    """
    ⚠️  Deprecation: the PhoenixKit user dashboard (/dashboard) is deprecated.
    You have it switched on with `config :phoenix_kit, user_dashboard_enabled: true`,
    so it keeps working exactly as before — no action needed right now.
    In a future release it will be removed and its functionality folded into the
    unified admin panel (/admin), which shows different sections based on each
    user's permissions. Nothing in PhoenixKit links to /dashboard any more.
    """
  end

  @doc """
  Notice that `:user_dashboard_enabled` now defaults to `false`.

  For a host upgrading across the flip that never wrote the key — it took the
  old default without ever choosing it, and `/dashboard` will stop routing on
  the next compile. Print only when
  `PhoenixKit.Config.user_dashboard_configured?/0` is false; a host that set
  the key either way already made a decision.
  """
  @spec user_dashboard_default_changed() :: String.t()
  def user_dashboard_default_changed do
    """
    ℹ️  Heads-up: `:user_dashboard_enabled` now defaults to **false**.

    The deprecated user dashboard (/dashboard, /dashboard/settings) is no longer
    routed unless you ask for it. Its job has moved into /admin, which shows each
    visitor the sections their permissions allow — and greets a visitor holding
    no permissions rather than bouncing them. Nothing in PhoenixKit links to
    /dashboard any more.

    If your app links to /dashboard, or you built pages onto it with
    `mix phoenix_kit.gen.user.dashboard`, keep it by adding to config.exs:

        config :phoenix_kit, user_dashboard_enabled: true

    Nothing has been deleted — that one line restores the routes unchanged.
    """
  end
end
