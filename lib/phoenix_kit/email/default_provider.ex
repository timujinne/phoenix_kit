defmodule PhoenixKit.Email.DefaultProvider do
  @moduledoc """
  No-op email provider. Used when phoenix_kit_emails package is not installed.

  - Interception: passes emails through unchanged, no tracking
  - AWS: returns empty/false → Mailer uses static config only
  """
  @behaviour PhoenixKit.Email.Provider

  # Interception — pass through, no tracking
  @impl true
  def intercept_before_send(email, _opts), do: email
  @impl true
  def handle_after_send(_email, _result), do: :ok
  # No package, no queue — every message is sent on the calling process.
  @impl true
  def maybe_enqueue(_email, _opts), do: :continue

  # AWS — not configured without package
  @impl true
  def get_aws_region, do: ""
  @impl true
  def get_aws_access_key, do: ""
  @impl true
  def get_aws_secret_key, do: ""
  @impl true
  def aws_configured?, do: false

  # Test email — not supported without emails package
  @impl true
  def send_test_tracking_email(_recipient_email, _user_uuid), do: {:error, :not_supported}

  # Provider detection — basic mapping
  @impl true
  def adapter_to_provider_name(nil, default), do: default
  def adapter_to_provider_name(Swoosh.Adapters.AmazonSES, _), do: "amazon_ses"
  def adapter_to_provider_name(Swoosh.Adapters.Mailgun, _), do: "mailgun"
  def adapter_to_provider_name(Swoosh.Adapters.Sendgrid, _), do: "sendgrid"
  def adapter_to_provider_name(Swoosh.Adapters.SMTP, _), do: "smtp"
  def adapter_to_provider_name(Swoosh.Adapters.Postmark, _), do: "postmark"
  def adapter_to_provider_name(Swoosh.Adapters.Local, _), do: "local"
  def adapter_to_provider_name(Swoosh.Adapters.Test, _), do: "test"
  def adapter_to_provider_name(_adapter, default), do: default
end
