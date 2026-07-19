defmodule PhoenixKit.Mailer do
  @moduledoc """
  Mailer module for PhoenixKit emails.

  This module handles sending emails such as
  confirmation emails, password reset emails, magic link emails, etc.

  It can work in two modes:
  1. **Built-in mode**: Uses PhoenixKit's own Swoosh mailer (default)
  2. **Delegation mode**: Uses the parent application's mailer when configured

  ## Configuration

  To use your application's mailer instead of PhoenixKit's built-in one:

      config :phoenix_kit,
        mailer: MyApp.Mailer

  When delegation is configured, all emails will be sent through your application's
  mailer, allowing you to use a single mailer configuration across your entire application.
  """

  use Swoosh.Mailer, otp_app: :phoenix_kit

  import Swoosh.Email

  alias PhoenixKit.Email.Provider
  alias PhoenixKit.Integrations
  alias PhoenixKit.Mailer.SmtpTransport
  alias PhoenixKit.Users.Auth.User

  require Logger

  # Soft dependency: the optional `emails` package (not a dependency of
  # core) owns the recipient blocklist (hard bounces, spam complaints,
  # manual blocks). Referencing it as a bare module name costs nothing at
  # compile time; `check_recipient_allowed/1` below guards every call with
  # `Code.ensure_loaded?/1`, so this file has no hard dependency on the
  # optional package and every recipient is implicitly allowed when it
  # isn't installed.
  #
  # We deliberately call `check_blocklist/1`, NOT `check_limits/1`:
  # `check_limits/1` additionally enforces the emails module's per-recipient
  # (100/h) and GLOBAL (10_000/h) send caps, which are not gated by any
  # enable flag. Wiring those in here would silently throttle every outbound
  # email app-wide (auth mail included) and would cap bulk newsletter
  # broadcasts at 10k/hour. Send pacing/quotas belong to the newsletters
  # send-profile limits (roadmap Phase 5, per-profile atomic caps) — one
  # limiter, not two competing ones.
  @emails_rate_limiter PhoenixKit.Modules.Emails.RateLimiter

  @doc """
  Gets the mailer module to use for sending emails.

  Returns the configured parent application mailer if set,
  otherwise returns the built-in PhoenixKit.Mailer.

  ## Examples

      iex> PhoenixKit.Mailer.get_mailer()
      MyApp.Mailer  # if configured

      iex> PhoenixKit.Mailer.get_mailer()
      PhoenixKit.Mailer  # default
  """
  def get_mailer do
    PhoenixKit.Config.get(:mailer, __MODULE__)
  end

  @doc """
  Sends an email using a template from the database.

  This is the main function for sending emails using PhoenixKit's template system.
  It automatically:
  - Loads the template by name
  - Renders it with provided variables
  - Tracks template usage
  - Sends the email with tracking
  - Logs to EmailSystem

  ## Parameters

  - `template_name` - Name of the template in the database (e.g., "welcome_email")
  - `recipient` - Email address (string) or {name, email} tuple
  - `variables` - Map of variables to substitute in the template
  - `opts` - Additional options:
    - `:user_uuid` - Associate email with a user (for tracking)
    - `:campaign_id` - Campaign identifier (for analytics)
    - `:from` - Override from address (default: configured from_email)
    - `:reply_to` - Reply-to address
    - `:metadata` - Additional metadata map for tracking

  ## Returns

  - `{:ok, email}` - Email sent successfully
  - `{:error, :template_not_found}` - Template doesn't exist
  - `{:error, :template_inactive}` - Template is not active
  - `{:error, reason}` - Other error

  ## Examples

      # Simple welcome email
      PhoenixKit.Mailer.send_from_template(
        "welcome_email",
        "user@example.com",
        %{"user_name" => "John", "url" => "https://app.com"}
      )

      # With user tracking
      PhoenixKit.Mailer.send_from_template(
        "password_reset",
        {"Jane Doe", "jane@example.com"},
        %{"reset_url" => "https://app.com/reset/token123"},
        user_uuid: user.uuid,
        campaign_id: "password_recovery"
      )

      # With metadata
      PhoenixKit.Mailer.send_from_template(
        "order_confirmation",
        customer.email,
        %{"order_id" => "12345", "total" => "$99.99"},
        user_uuid: customer.uuid,
        campaign_id: "orders",
        metadata: %{order_id: order.id, amount: order.total}
      )
  """
  def send_from_template(template_name, recipient, variables \\ %{}, opts \\ [])
      when is_binary(template_name) do
    # Get the template from database
    case Provider.current().get_active_template_by_name(template_name) do
      nil ->
        {:error, :template_not_found}

      template ->
        # Ensure template is active
        if template.status == "active" do
          # Render template with variables in the requested locale
          locale = Keyword.get(opts, :locale, "en")
          rendered = Provider.current().render_template(template, variables, locale)

          # Build email
          email =
            new()
            |> to(recipient)
            |> from(Keyword.get(opts, :from, {get_from_name(), get_from_email()}))
            |> subject(rendered.subject)
            |> html_body(rendered.html_body)
            |> text_body(rendered.text_body)

          # Add reply-to if provided
          email =
            if reply_to = Keyword.get(opts, :reply_to) do
              reply_to(email, reply_to)
            else
              email
            end

          # Track template usage
          Provider.current().track_usage(template)

          # Extract source_module from template metadata
          source_module = Provider.current().get_source_module(template)

          # Prepare delivery options with category and source_module from template
          delivery_opts =
            opts
            |> Keyword.put(:template_name, template_name)
            |> Keyword.put(:template_uuid, template.uuid)
            |> Keyword.put_new(:campaign_id, template.category)
            |> Keyword.put(:category, template.category)
            |> Keyword.put_new(:source_module, source_module)
            |> Keyword.put(:provider, detect_provider())

          # Send email with tracking
          deliver_email(email, delivery_opts)
        else
          {:error, :template_inactive}
        end
    end
  end

  @doc """
  Delivers an email using the appropriate mailer.

  If Settings key `"default_email_integration_uuid"` is set and resolves to
  an Integrations connection with valid credentials, delivery is routed
  through that connection via `deliver_via_integration/3` (set on the core
  Email Sending settings page). Otherwise, if a parent application mailer is
  configured, delegates to it; failing that, uses the built-in PhoenixKit
  mailer. The setting being absent, blank, or pointing at a
  deleted/unconfigured connection is a no-op — behavior is unchanged from
  before this routing existed.

  This function also integrates with the email tracking system to log
  outgoing emails when tracking is enabled. Recipients blocklisted by the
  emails module (hard bounces, complaints, manual blocks — in `to`, `cc` or
  `bcc`) are rejected before any tracking or delivery is attempted; see
  `check_recipient_allowed/1`. Send-rate limits are deliberately NOT enforced
  here — see the soft-dependency note at the top of this module.
  """
  def deliver_email(email, opts \\ []) do
    case default_send_integration_uuid() do
      {:ok, uuid} -> deliver_via_integration(email, uuid, opts)
      :error -> deliver_via_configured_mailer(email, opts)
    end
  end

  defp deliver_via_configured_mailer(email, opts) do
    with :ok <- check_recipient_allowed(email) do
      # Intercept email for tracking before sending
      tracked_email = Provider.current().intercept_before_send(email, opts)

      mailer = get_mailer()

      result =
        if mailer == __MODULE__ do
          # Use built-in mailer with runtime config for AWS
          deliver_with_runtime_config(tracked_email, mailer)
        else
          # Check if parent mailer also uses AWS SES
          app = PhoenixKit.Config.get_parent_app()
          config = Application.get_env(app, mailer, [])

          if config[:adapter] == Swoosh.Adapters.AmazonSES do
            # Parent mailer uses AWS SES, provide runtime config
            deliver_with_runtime_config(tracked_email, mailer, app)
          else
            # Non-AWS mailer, use standard delivery
            mailer.deliver(tracked_email)
          end
        end

      # Handle post-send tracking updates
      Provider.current().handle_after_send(tracked_email, result)

      result
    end
  end

  # Resolves the operator-chosen default send integration, if any. Only
  # returns `{:ok, uuid}` when the setting is a non-blank uuid that actually
  # resolves to a connection with valid credentials — a stale or deleted
  # uuid falls back to the built-in/parent-mailer path (`:error`) rather
  # than failing the send outright. NOT used by `deliver_via_integration/3`
  # itself (which takes an explicit uuid), so there is no recursion risk
  # here: this function never calls `deliver_email/2`.
  #
  # Why credentials-present (`connected?/1`) is the gate and a status check
  # would be wrong (review question, settled 2026-07-16): `disconnect/2`
  # WIPES stored credentials, so "disconnected must not send" already holds —
  # `connected?/1` is false without creds. The remaining case is status
  # "error" (a failed Test Connection) with credentials still stored: that
  # one deliberately still routes, because a stale or false-negative test
  # silently rerouting ALL mail to the built-in path is the worse surprise —
  # a genuinely broken integration fails the send loudly instead.
  @spec default_send_integration_uuid() :: {:ok, String.t()} | :error
  defp default_send_integration_uuid do
    with uuid when is_binary(uuid) and uuid != "" <-
           PhoenixKit.Settings.get_setting("default_email_integration_uuid"),
         true <- Integrations.connected?(uuid) do
      {:ok, uuid}
    else
      _ -> :error
    end
  end

  # Deliver email with runtime configuration for AWS SES
  defp deliver_with_runtime_config(email, mailer, app \\ :phoenix_kit) do
    config =
      if app == :phoenix_kit do
        # Use PhoenixKit config for built-in mailer
        PhoenixKit.Config.get(mailer, [])
      else
        # Use parent app config for parent mailer
        PhoenixKit.Config.get_parent_app_config(mailer, [])
      end

    # If using AWS SES, override with runtime settings from DB
    runtime_config =
      if config[:adapter] == Swoosh.Adapters.AmazonSES do
        if Provider.current().aws_configured?() do
          config
          |> Keyword.put(:region, Provider.current().get_aws_region())
          |> Keyword.put(:access_key, Provider.current().get_aws_access_key())
          |> Keyword.put(:secret, Provider.current().get_aws_secret_key())
        else
          config
        end
      else
        config
      end

    # Use Swoosh.Mailer.deliver with runtime config
    Swoosh.Mailer.deliver(email, runtime_config)
  end

  @doc """
  Delivers an email via a specific Integrations connection (AWS SES,
  universal SMTP, or Brevo API), selected by the connection's `uuid`.

  Unlike `deliver_email/2`, this does **not** go through
  `deliver_with_runtime_config/2` — that path is hardcoded to AWS SES
  (`config[:adapter] == Swoosh.Adapters.AmazonSES`, credentials only from
  `Provider.current().get_aws_*`), so a Brevo or SMTP send routed through
  it would be misrouted or ignored. This function resolves the Swoosh
  adapter and config directly from the chosen integration's stored
  credentials instead, while preserving the same interception seam
  `deliver_email/2` uses so tracking keeps working.

  ## Returns

  - `{:ok, term()}` — delivered
  - `{:error, {:blocked, atom()}}` — a recipient (`to`/`cc`/`bcc`) is
    blocklisted by the emails module (checked before the integration is even
    resolved). Send-rate limits are NOT enforced here — see the module's
    soft-dependency note.
  - `{:error, :not_configured | :deleted}` — the integration uuid didn't resolve
  - `{:error, {:unsupported_provider, String.t()} | :unsupported_provider}` —
    the integration's provider has no known Swoosh adapter mapping (the bare
    atom when the credentials carry no provider key at all)
  - `{:error, {:invalid_smtp_port, term()}}` — the SMTP connection's port is
    not a number
  - `{:error, {:incomplete_credentials, [atom()]}}` — a required field for the
    resolved provider (e.g. `:aws_region`, `:host`, `:api_key`) is blank. This
    can happen even on a `connected?/1`-passing integration: a status of
    "connected" is sticky (`Integrations.save_setup/3` doesn't recompute it
    on later edits), so a required field can be blanked out after the fact
    without the connection ever un-connecting. The listed atoms are field
    *names* only — never values, and never the raw creds map — since the
    whole point is not leaking the other, still-present secrets alongside it.
  - `{:error, :no_ca_store}` — SMTP only, and a **behaviour change**: there is no
    system CA bundle, so the relay's certificate cannot be verified and the
    password would go out to an unauthenticated server. Sending stops. It used to
    proceed with `verify: :verify_none`, which is why slim images (distroless,
    scratch, some Alpine builds) never noticed they had no CA store. Install one
    (e.g. `ca-certificates`) to restore sending. A relay with no credentials to
    protect still degrades rather than failing.
  """
  @spec deliver_via_integration(Swoosh.Email.t(), String.t(), keyword()) ::
          {:ok, term()} | {:error, term()}
  def deliver_via_integration(email, integration_uuid, opts \\ [])
      when is_binary(integration_uuid) do
    with :ok <- check_recipient_allowed(email),
         {:ok, creds} <- Integrations.get_credentials(integration_uuid),
         {:ok, {adapter, config}} <- swoosh_config_for(creds) do
      # Tell the tracking interceptor which provider actually sent this. Without
      # it, `detect_provider/2` falls back to the host app's static mailer
      # adapter (e.g. SES) and mis-attributes SMTP/Brevo integration sends
      # (plus a "no provider data" warning per send). `put_new` lets an explicit
      # caller override win.
      tracked_opts = Keyword.put_new(opts, :provider, creds["provider"])
      tracked_email = Provider.current().intercept_before_send(email, tracked_opts)
      result = Swoosh.Mailer.deliver(tracked_email, [adapter: adapter] ++ config)
      Provider.current().handle_after_send(tracked_email, result)
      result
    end
  end

  @doc false
  # Maps an Integrations connection's decrypted credentials to a Swoosh
  # `{adapter, config}` pair. Not `defp` so `deliver_via_integration/3`'s
  # provider selection can be unit-tested without triggering real
  # delivery — `@doc false` because it's an internal seam, not part of
  # the public API. The returned config carries DECRYPTED secrets — callers
  # must never log or `inspect` it.
  @spec swoosh_config_for(map()) :: {:ok, {module(), keyword()}} | {:error, term()}
  def swoosh_config_for(%{"provider" => "aws_ses"} = creds) do
    with :ok <-
           require_fields(creds, [
             {"access_key", :access_key},
             {"secret_key", :secret_key},
             {"aws_region", :aws_region}
           ]) do
      {:ok,
       {Swoosh.Adapters.AmazonSES,
        [
          region: creds["aws_region"],
          access_key: creds["access_key"],
          secret: creds["secret_key"]
        ]}}
    end
  end

  def swoosh_config_for(%{"provider" => "smtp"} = creds) do
    # Only `host` is gated here — it's the sole field Swoosh's own SMTP
    # adapter declares `required_config` (`relay`), and therefore the only
    # one whose absence trips `Swoosh.Adapter.validate_config/2`'s leak
    # (see require_fields/2 below). `SmtpTransport.config/1` itself
    # tolerates a blank host by design (the pre-save "test what you typed"
    # probe in Integrations.Validators calls it directly, before a host has
    # necessarily been filled in) — that call site is unaffected, since it
    # never goes through this function.
    with :ok <- require_fields(creds, [{"host", :host}]) do
      case SmtpTransport.config(creds) do
        {:ok, options} -> {:ok, {Swoosh.Adapters.SMTP, options}}
        {:error, _reason} = error -> error
      end
    end
  end

  def swoosh_config_for(%{"provider" => "brevo_api"} = creds) do
    with :ok <- require_fields(creds, [{"api_key", :api_key}]) do
      {:ok, {Swoosh.Adapters.Brevo, [api_key: creds["api_key"]]}}
    end
  end

  def swoosh_config_for(%{"provider" => provider}),
    do: {:error, {:unsupported_provider, provider}}

  def swoosh_config_for(_creds), do: {:error, :unsupported_provider}

  # Guards against building a secret-bearing Swoosh config with a required
  # field missing. Without this, a connection whose status is "connected"
  # (set once by a real Test Connection) but whose required field was
  # blanked afterward — `Integrations.save_setup/3`'s `maybe_set_status/2`
  # deliberately leaves an already-"connected" status untouched on later
  # edits — still passes `connected?/1` and reaches `Swoosh.Mailer.deliver/2`,
  # which calls the adapter's own `validate_config/1`
  # (`Swoosh.Adapter.validate_config/2`). That raises `ArgumentError` with
  # `inspect(config)` in the message — dumping every OTHER decrypted secret
  # in the same config (access_key/secret/password/api_key) into the
  # exception, and from there into crash logs, an error tracker, or a flash
  # message. Reporting only field NAMES here, never values, keeps a
  # missing-credential failure from becoming a credential leak.
  @spec require_fields(map(), [{String.t(), atom()}]) ::
          :ok | {:error, {:incomplete_credentials, [atom()]}}
  defp require_fields(creds, fields) do
    missing = for {key, name} <- fields, blank?(creds[key]), do: name

    if missing == [], do: :ok, else: {:error, {:incomplete_credentials, missing}}
  end

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false

  defp check_recipient_allowed(%Swoosh.Email{} = email) do
    # cc/bcc too, not just to: a suppression list with a hole in it is a
    # compliance problem, and this Mailer carries all app mail, not only
    # newsletters (which only ever populate `to`).
    (email.to ++ (email.cc || []) ++ (email.bcc || []))
    |> Enum.reduce_while(:ok, fn {_name, address}, :ok ->
      case check_blocklisted(address) do
        :ok -> {:cont, :ok}
        {:blocked, reason} -> {:halt, {:error, {:blocked, reason}}}
      end
    end)
  end

  defp check_blocklisted(address) do
    if Code.ensure_loaded?(@emails_rate_limiter) and
         function_exported?(@emails_rate_limiter, :check_blocklist, 1) do
      # apply/3 intentionally, to avoid compile-time module resolution --
      # a direct call would fail `--warnings-as-errors` when the optional
      # emails package isn't a dependency (the compiler can prove the module
      # is undefined).
      # credo:disable-for-next-line Credo.Check.Refactor.Apply
      apply(@emails_rate_limiter, :check_blocklist, [address])
    else
      :ok
    end
  rescue
    error ->
      # Fail open: this gate sits in front of ALL outbound mail (auth
      # included), so a transient DB hiccup must not take delivery down.
      Logger.error("Recipient blocklist check failed, allowing send: #{inspect(error)}")
      :ok
  end

  @doc """
  Sends a magic link email to the user.

  Uses the 'magic_link' template from the database if available,
  falls back to hardcoded template if not found.

  ## Examples

      iex> PhoenixKit.Mailer.send_magic_link_email(user, "https://app.com/magic/token123")
      {:ok, %Swoosh.Email{}}
  """
  def send_magic_link_email(%User{} = user, magic_link_url) when is_binary(magic_link_url) do
    # Variables for template substitution
    template_variables = %{
      "user_email" => user.email,
      "magic_link_url" => magic_link_url
    }

    # Try to get template from database, fallback to text-only
    {subject, html_body, text_body, db_template} =
      case Provider.current().get_active_template_by_name("magic_link") do
        nil ->
          {
            "Your secure login link",
            nil,
            magic_link_text_body(user, magic_link_url),
            nil
          }

        template ->
          rendered = Provider.current().render_template(template, template_variables)
          {rendered.subject, rendered.html_body, rendered.text_body, template}
      end

    email =
      new()
      |> to({user.email, user.email})
      |> from({get_from_name(), get_from_email()})
      |> subject(subject)
      |> html_body(html_body)
      |> text_body(text_body)

    # Track template usage if using database template
    if db_template, do: Provider.current().track_usage(db_template)

    deliver_email(email,
      user_uuid: user.uuid,
      template_name: "magic_link",
      campaign_id: "authentication",
      category: "system",
      source_module: "users",
      provider: detect_provider()
    )
  end

  # Text version of the magic link email
  defp magic_link_text_body(_user, magic_link_url) do
    """
    Your login link: #{magic_link_url}
    This link expires in 15 minutes.
    """
  end

  # Detect current email provider from configuration
  defp detect_provider do
    mailer = get_mailer()

    if mailer == __MODULE__ do
      detect_builtin_provider()
    else
      detect_parent_app_provider(mailer)
    end
  end

  # Detect provider for built-in PhoenixKit mailer
  defp detect_builtin_provider do
    config = PhoenixKit.Config.get(PhoenixKit.Mailer, [])
    adapter = Keyword.get(config, :adapter)
    Provider.current().adapter_to_provider_name(adapter, "phoenix_kit_builtin")
  end

  # Detect provider for parent application mailer
  defp detect_parent_app_provider(mailer) when is_atom(mailer) do
    config = PhoenixKit.Config.get_parent_app_config(mailer, [])
    adapter = Keyword.get(config, :adapter)
    Provider.current().adapter_to_provider_name(adapter, "parent_app_mailer")
  end

  defp detect_parent_app_provider(_mailer), do: "unknown"

  @doc """
  Gets the effective "from" email address.

  Priority: Settings Database (runtime) > Config file (compile-time) >
  built-in default (`"noreply@localhost"`). Public so the Email Sending
  settings page can display the value that's actually in effect, even
  when no Settings override is set.
  """
  @spec get_from_email() :: String.t()
  def get_from_email do
    # Priority 1: Settings Database (runtime)
    case PhoenixKit.Settings.get_setting("from_email") do
      nil ->
        # Priority 2: Config file (compile-time, fallback)
        case PhoenixKit.Config.get(:from_email) do
          {:ok, email} -> email
          # Priority 3: Default
          _ -> "noreply@localhost"
        end

      email ->
        email
    end
  end

  @doc """
  Gets the effective "from" name.

  Priority: Settings Database (runtime) > Config file (compile-time) >
  built-in default (`"PhoenixKit"`). Public so the Email Sending settings
  page can display the value that's actually in effect, even when no
  Settings override is set.
  """
  @spec get_from_name() :: String.t()
  def get_from_name do
    # Priority 1: Settings Database (runtime)
    case PhoenixKit.Settings.get_setting("from_name") do
      nil ->
        # Priority 2: Config file (compile-time, fallback)
        case PhoenixKit.Config.get(:from_name) do
          {:ok, name} -> name
          # Priority 3: Default
          _ -> "PhoenixKit"
        end

      name ->
        name
    end
  end
end
