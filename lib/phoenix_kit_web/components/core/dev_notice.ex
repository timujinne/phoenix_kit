defmodule PhoenixKitWeb.Components.Core.DevNotice do
  @moduledoc """
  Development mode notice component for the local mailbox.

  Only renders when the mailer is configured to run locally
  (`PhoenixKit.Config.mailer_local?() == true`).
  """

  use Phoenix.Component

  import PhoenixKitWeb.Components.Core.Icon

  alias PhoenixKit.Config

  @doc """
  Renders a development mode notice pointing to the local mailbox.

  Only renders in local development mode when `Config.mailer_local?()` is true.

  ## Attributes

  - `message` - The email type shown after "mailbox for" (default: "confirmation emails")
  - `class` - Additional CSS classes for the alert div (default: "mt-4")

  ## Examples

      <.dev_mailbox_notice />
      <.dev_mailbox_notice message="reset emails" />
      <.dev_mailbox_notice message="magic link emails" class="mt-4 w-full sm:w-fit" />

  """
  attr :message, :string, default: "confirmation emails"
  attr :class, :string, default: "mt-4"

  def dev_mailbox_notice(assigns) do
    assigns = assign(assigns, :mailbox_enabled, mailbox_enabled?())

    ~H"""
    <div :if={Config.mailer_local?()} class={["alert alert-info text-sm", @class]}>
      <.icon name="hero-information-circle" class="stroke-current shrink-0 h-6 w-6" />
      <span :if={@mailbox_enabled}>
        Development mode: check the local mailbox for {@message}
      </span>
      <span :if={!@mailbox_enabled}>
        Development mode: outgoing email is written to the server log
      </span>
    </div>
    """
  end

  # This renders on the public auth pages: a dead database must read as
  # "mailbox closed", never break the page. Deliberately NO link to
  # /dev/mailbox in either branch — the page is unauthenticated, and an
  # anchor on the exact pages that trigger token mail is a map for
  # strangers, not just a convenience for the developer (issue #687).
  defp mailbox_enabled? do
    PhoenixKit.Settings.get_boolean_setting("dev_mailbox_enabled", false)
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end
end
