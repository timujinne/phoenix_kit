defmodule PhoenixKit.Integrations.Validators do
  @moduledoc """
  Real connection checks for providers that cannot be validated with a simple
  authenticated HTTP GET.

  `PhoenixKit.Integrations` falls through to `:ok` for any provider that declares
  no validation. For the e-mail providers that meant "Test Connection" verified
  *nothing*: the connection was stamped `"connected"` without a single byte
  leaving the box, so an operator who pasted a wrong key or a bad SMTP password
  saw a green check and then a failing send.

  A check that always says yes is worse than no check — but so is one that says
  no when the configuration is fine. These validators are therefore careful in
  both directions:

    * a relay that authenticates by IP and offers no `AUTH` verb passes (the
      credentials are simply unused — sending works, so the check is green);
    * SES credentials scoped to `ses:SendEmail` only — the least-privilege policy
      AWS itself recommends — pass, even though they cannot read the send quota.

  Every check runs through `PhoenixKit.Integrations.Probe`, which bounds it with
  a hard deadline and isolates it from the caller — the libraries underneath
  bound neither themselves nor their crashes, and both call sites are LiveView
  callbacks.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  require Logger

  alias PhoenixKit.AWS.CredentialsVerifier
  alias PhoenixKit.Integrations.Probe
  alias PhoenixKit.Mailer.SmtpTransport
  alias PhoenixKit.Utils.Number

  @http_timeout 15_000

  @doc """
  Validates AWS SES credentials against the SES API itself.

  Asks SES for the account's send quota — the cheapest call that proves the
  credentials are real. Built as a raw `ExAws.Operation.Query`, so it needs no
  `ex_aws_ses` dependency.

  The endpoint host is passed explicitly rather than left to ExAws, whose region
  resolution is a hard-coded prefix allowlist (`~r/^(us|eu|af|ap|sa|ca|me)-.../`)
  that silently yields *no host at all* for newer regions such as `il-central-1`
  — while the send path (`Swoosh.Adapters.AmazonSES`) simply interpolates the
  region and works. Validate and send must resolve the same endpoint.
  """
  @spec aws_ses(map()) :: :ok | {:ok, String.t()} | {:error, String.t()}
  def aws_ses(data) do
    region = data["aws_region"]

    cond do
      blank?(data["access_key"]) or blank?(data["secret_key"]) ->
        {:error, gettext("Incomplete credentials")}

      # ExAws would otherwise default a blank region to us-east-1 and happily
      # report success, while the send path builds "email..amazonaws.com" from
      # the same blank region and raises.
      blank?(region) ->
        {:error, gettext("Region is required")}

      true ->
        # The send-quota probe stays the AUTH VERDICT — its transient-
        # signature retry logic is what keeps good keys from being called
        # invalid. The CredentialsVerifier sweep (the same one the Emails
        # settings page runs) runs AFTERWARDS in its own probe and is
        # strictly additive: a passing verdict may gain account identity
        # and permission context, but enrichment failing, exiting, or
        # timing out can never downgrade the verdict itself.
        case Probe.run(fn -> request_send_quota(region, data) end) do
          :ok -> ok_with_note(region, data, nil)
          {:ok, quota_note} -> ok_with_note(region, data, quota_note)
          error -> error
        end
    end
  end

  defp ok_with_note(region, data, quota_note) do
    case enrich_note(region, data, quota_note) do
      nil -> :ok
      note -> {:ok, note}
    end
  end

  defp enrich_note(region, data, quota_note) do
    # The probe contract carries strings, so the note is assembled inside the
    # closure; :ok = "nothing to add", any probe failure = keep the quota note.
    result =
      Probe.run(fn ->
        identity =
          case CredentialsVerifier.verify_credentials(
                 data["access_key"],
                 data["secret_key"],
                 region
               ) do
            {:ok, %{account_id: id}} -> gettext("Account %{id}", id: id)
            _ -> nil
          end

        perms =
          case CredentialsVerifier.check_permissions(
                 data["access_key"],
                 data["secret_key"],
                 region
               ) do
            {:ok, perms} -> perms
            _ -> nil
          end

        case aws_note(identity, perms, quota_note) do
          nil -> :ok
          note -> {:ok, note}
        end
      end)

    case result do
      {:ok, note} -> note
      :ok -> nil
      _ -> quota_note
    end
  end

  @doc false
  # Pure note assembly, public for tests. Only GRANTED management APIs are
  # listed — a least-privilege ses:SendEmail-only key (which the verdict
  # deliberately passes) must not read as "SES denied" here, so denied
  # services are omitted rather than dashed out.
  def aws_note(identity, perms, quota_note) do
    granted =
      for {key, label} <- [ses: "SES", sqs: "SQS", sns: "SNS"],
          is_map(perms),
          perms |> Map.get(key, %{}) |> Map.values() |> Enum.any?(&(&1 == :granted)),
          do: label

    services =
      case granted do
        [] -> nil
        list -> gettext("management API: %{services}", services: Enum.join(list, ", "))
      end

    [identity, services, quota_note]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
    |> case do
      "" -> nil
      note -> note
    end
  end

  @doc """
  Validates an Amazon Bedrock API key against the Bedrock control plane.

  Lists foundation models in the configured region — the cheapest call that
  proves both the key and the region at once. Bedrock long-term API keys
  authenticate with a plain Bearer header (no SigV4), the same header the
  OpenAI-compatible runtime endpoint accepts — a green check proves the
  completions path can authenticate IN THIS REGION; an AI endpoint must
  point its base URL at the same region for that guarantee to carry over.
  """
  @spec amazon_bedrock(map()) :: :ok | {:ok, String.t()} | {:error, String.t()}
  def amazon_bedrock(data) do
    region = String.trim(data["aws_region"] || "")
    api_key = String.trim(data["api_key"] || "")

    cond do
      blank?(api_key) ->
        {:error, gettext("No credentials configured")}

      blank?(region) ->
        {:error, gettext("Region is required")}

      # A malformed region would send the probe to a non-AWS hostname.
      not valid_aws_region?(region) ->
        {:error, gettext("Invalid region format (expected e.g. eu-central-1)")}

      true ->
        Probe.run(fn -> request_bedrock_models(region, api_key) end)
    end
  end

  @doc false
  # Pure, public for tests. The prefix is 2-4 letters (us-east-1 …
  # eusc-de-east-1), the suffix a small number.
  def valid_aws_region?(region) when is_binary(region) do
    Regex.match?(~r/^[a-z]{2,4}(-[a-z]+)+-\d{1,2}$/, region)
  end

  def valid_aws_region?(_), do: false

  defp request_bedrock_models(region, api_key) do
    # retry: false — the outer Probe deadline is the only clock here; Req's
    # default transient retries would sleep through most of it.
    case Req.get("#{bedrock_host(region)}/foundation-models",
           headers: [{"authorization", "Bearer " <> api_key}],
           receive_timeout: @http_timeout,
           retry: false
         ) do
      {:ok, %{status: 200, body: %{"modelSummaries" => models}}} when is_list(models) ->
        {:ok, bedrock_models_note(length(models), region)}

      {:ok, %{status: 200}} ->
        :ok

      {:ok, %{status: 401}} ->
        {:error, gettext("Invalid credentials")}

      # The most likely 403 is a key whose IAM identity lacks
      # bedrock:CallWithBearerToken (or ListFoundationModels) — the key
      # itself authenticated, so "invalid credentials" would send the
      # operator off to reissue a perfectly good key.
      {:ok, %{status: 403}} ->
        {:error,
         gettext(
           "Key authenticated but not authorised in %{region} — allow bedrock:CallWithBearerToken (and ListFoundationModels) on its IAM identity, or check the key was issued for this region",
           region: region
         )}

      {:ok, %{status: status}} ->
        {:error, gettext("Bedrock error %{status}", status: status)}

      {:error, reason} ->
        Logger.warning("Bedrock connection check failed: #{inspect(reason)}")
        {:error, gettext("Could not reach Bedrock in %{region}", region: region)}
    end
  end

  @doc false
  # The China partition answers on .amazonaws.com.cn — the global host does not
  # resolve there at all, which would surface as "could not reach Bedrock".
  def bedrock_host("cn-" <> _ = region), do: "https://bedrock.#{region}.amazonaws.com.cn"
  def bedrock_host(region), do: "https://bedrock.#{region}.amazonaws.com"

  @doc false
  # Pure, public for tests. Sidesteps plural forms; the count is the region's
  # whole catalog, not the models this account may invoke — say so.
  def bedrock_models_note(count, region) do
    gettext("Model catalog in %{region}: %{count} (grants are configured separately)",
      count: count,
      region: region
    )
  end

  @doc """
  Validates an SMTP relay by opening a real session and authenticating.

  The connection options come from `PhoenixKit.Mailer.SmtpTransport.config/1`, so
  the check exercises exactly the transport a real send uses — one source of
  truth, no drift between "tested" and "sent".

  Forcing AUTH for the probe is deliberate: with gen_smtp's `:if_available` the
  AUTH exchange is attempted but its failure is tolerated, so a wrong password
  would still open a session and the check would pass. The operator's `auth`
  setting is honored in one direction only — `never` stays `never` (there are no
  credentials to prove), while `if_available` is upgraded to `always` for the
  probe so a bad password fails the check. A connection with no username and no
  password stays `never` for the same reason as an explicit `never`. A relay that
  advertises no `AUTH` verb at all is a different case, and is treated as a pass
  — see the module doc.
  """
  @spec smtp(map()) :: :ok | {:ok, String.t()} | {:error, String.t()}
  def smtp(data) do
    case SmtpTransport.config(data) do
      {:ok, options} ->
        Probe.run(fn -> open_smtp(options) end)

      {:error, {:invalid_smtp_port, port}} ->
        {:error, gettext("Invalid port: %{port}", port: inspect(port))}

      {:error, :no_ca_store} ->
        {:error,
         gettext("No system CA certificates found, so the relay's certificate cannot be verified")}

      {:error, :invalid_ca_cert} ->
        {:error,
         gettext(
           "The CA certificate is not a valid PEM bundle (expected a -----BEGIN CERTIFICATE----- block)"
         )}

      {:error, {:invalid_timeout, value}} ->
        {:error, gettext("Invalid timeout: %{value}", value: inspect(value))}

      {:error, {key, value}}
      when key in [:invalid_security, :invalid_verify_cert, :invalid_auth] ->
        {:error,
         gettext("Invalid %{setting}: %{value}",
           setting: to_string(key) |> String.replace_prefix("invalid_", ""),
           value: inspect(value)
         )}

      # This case runs OUTSIDE Probe.run and its rescue, so a reason added to
      # SmtpTransport later would raise CaseClauseError straight out of a
      # LiveView callback. Say something useless-but-safe instead.
      {:error, reason} ->
        {:error, gettext("Invalid SMTP settings: %{reason}", reason: inspect(reason))}
    end
  end

  # --- SMTP -----------------------------------------------------------------

  # `never` is the operator saying there are no credentials to prove, so leave it
  # alone; anything else becomes `always` so a wrong password fails the check
  # instead of being tolerated (see `smtp/1`'s doc).
  #
  # A relay configured with no login at all is the same case arrived at from the
  # other direction: forcing `always` there makes the probe demand an AUTH
  # exchange it has nothing to send, so a perfectly working IP-authenticated
  # relay would fail Test Connection while sending fine.
  defp probe_auth(options) do
    cond do
      Keyword.get(options, :auth, :if_available) == :never -> :never
      blank?(options[:username]) and blank?(options[:password]) -> :never
      true -> :always
    end
  end

  defp open_smtp(options) do
    probe_options =
      options
      |> Keyword.put(:auth, probe_auth(options))
      # gen_smtp retries a temporarily-failing relay once by default, which doubles
      # the time to a verdict and can push a slow failure past our deadline — the
      # operator would be told "did not respond in time" instead of what went wrong.
      # A real send still wants the retry; a check does not.
      |> Keyword.put(:retries, 0)

    case :gen_smtp_client.open(probe_options) do
      {:ok, socket} ->
        :gen_smtp_client.close(socket)
        :ok

      # The relay offers no AUTH verb — it authenticates by IP, or not at all.
      # The credentials are unused, a real send works, and `username`/`password`
      # are required fields the operator had to fill in with something. A red
      # cross here would be a lie about a working relay.
      {:error, _type, {:missing_requirement, _host, :auth}} ->
        Logger.info("SMTP relay advertises no AUTH; credentials are unused by this relay")
        :ok

      {:error, :bad_option, reason} ->
        {:error, describe_bad_option(reason)}

      {:error, _type, reason} ->
        {:error, describe_smtp_failure(reason)}
    end
  rescue
    # gen_smtp calls to_binary/1 on the username, which has no clause for nil —
    # reachable through the pre-save "test what you typed" probe, which does not
    # go through the credential gate. It is a wide net, so it leaves a trace: a
    # FunctionClauseError from anywhere else must not vanish as "incomplete".
    error in FunctionClauseError ->
      Logger.warning("SMTP connection check raised FunctionClauseError: #{inspect(error)}")
      {:error, gettext("Incomplete SMTP settings")}

    error ->
      Logger.warning("SMTP connection check failed: #{inspect(error)}")
      {:error, gettext("Could not reach the SMTP server")}
  catch
    :exit, reason ->
      Logger.warning("SMTP connection check exited: #{inspect(reason)}")
      {:error, describe_smtp_failure(reason)}
  end

  defp describe_bad_option(reason)
       when reason in [:no_relay, :no_credentials, :invalid_port],
       do: gettext("Incomplete SMTP settings")

  defp describe_bad_option(_reason), do: gettext("Invalid SMTP settings")

  defp describe_smtp_failure(reason) do
    text = reason |> inspect() |> String.downcase()

    cond do
      # gen_smtp reports a rejected login as {:permanent_failure, host, :auth_failed}
      String.contains?(text, ["auth_failed", "535", "authentication", "not authenticated"]) ->
        gettext("Invalid credentials")

      String.contains?(text, ["tls_failed", "ssl_not_started"]) ->
        gettext("TLS handshake failed")

      String.contains?(text, ["nxdomain", "econnrefused", "timeout", "ehostunreach"]) ->
        gettext("Could not reach the SMTP server")

      true ->
        gettext("SMTP server rejected the connection")
    end
  end

  # --- SES ------------------------------------------------------------------

  @doc false
  # `requester` is injectable so the confirm-retry — the behaviour that keeps a valid
  # key from being reported invalid — can be tested without talking to AWS.
  def request_send_quota(region, data, requester \\ &send_quota_request/2) do
    case requester.(region, data) do
      # Never call credentials invalid on a single 403. AWS briefly answers a
      # *correct* request with SignatureDoesNotMatch right after it has rejected
      # a bad signature from the same key — which is exactly the flow an operator
      # produces by pasting a wrong key, fixing it, and pressing Test again.
      # Telling them their good keys are invalid sends them off to reissue
      # credentials that were never the problem. Confirm before accusing.
      {:invalid, _} ->
        # A full second, not less: SES throttles GetSendQuota at about one request
        # per second, and the confirm-retry doubles our rate against it. Come back
        # too soon and the second call answers Throttling, which reports a genuinely
        # invalid key as "AWS SES is busy".
        Process.sleep(1_000)

        case requester.(region, data) do
          {:invalid, _} -> {:error, gettext("Invalid credentials")}
          confirmed -> confirmed
        end

      result ->
        result
    end
  end

  defp send_quota_request(region, data) do
    operation = %ExAws.Operation.Query{
      action: :get_send_quota,
      path: "/",
      params: %{"Action" => "GetSendQuota", "Version" => "2010-12-01"},
      service: :ses,
      parser: fn response, _action -> response end
    }

    operation
    |> ExAws.request(
      access_key_id: data["access_key"],
      secret_access_key: data["secret_key"],
      region: region,
      host: "email.#{region}.amazonaws.com",
      # ExAws retries transport errors ten times with backoff by default; an
      # unreachable endpoint would block for minutes. Two attempts survives a
      # single blip (SES throttles GetSendQuota aggressively) and still stays
      # well inside the outer deadline.
      #
      # All three keys are mandatory. ExAws merges this override with `Map.merge`,
      # so the list REPLACES the default wholesale — pass `max_attempts` alone and
      # the backoff keys vanish, leaving `ExAws.Request.backoff/2` to evaluate
      # `nil * :math.pow(2, attempt)`. It raises, the rescue below swallows it, and
      # the check silently performs no retries at all.
      retries: [max_attempts: 2, base_backoff_in_ms: 10, max_backoff_in_ms: 1_000],
      http_opts: [recv_timeout: 5_000, connect_timeout: 5_000]
    )
    |> case do
      {:ok, %{body: body}} ->
        case format_quota_note(body) do
          nil -> :ok
          note -> {:ok, note}
        end

      {:error, reason} ->
        interpret_ses_error(reason)
    end
  rescue
    error ->
      Logger.warning("SES connection check failed: #{inspect(error)}")
      {:error, gettext("Could not reach AWS SES")}
  catch
    # hackney reaches its connection pool through GenServer.call, which exits
    # rather than raising — `rescue` alone does not see it.
    :exit, reason ->
      Logger.warning("SES connection check exited: #{inspect(reason)}")
      {:error, gettext("Could not reach AWS SES")}
  end

  @doc false
  # Pure: an AWS error payload in, an operator-facing verdict out. Public so the
  # mapping can be tested against real SES bodies without a network round trip.
  def interpret_ses_error({:http_error, _status, response}) do
    case aws_error_code(response) do
      code
      when code in ~w(SignatureDoesNotMatch InvalidClientTokenId UnrecognizedClientException
                      InvalidAccessKeyId ExpiredToken TokenRefreshRequired) ->
        {:invalid, code}

      # SES throttles GetSendQuota hard (~1 request/second). Reporting a
      # throttle as "invalid credentials" would send an operator off to reissue
      # perfectly good keys — observed live while testing this very validator.
      code
      when code in ~w(Throttling ThrottlingException RequestExpired
                      ServiceUnavailable InternalFailure) ->
        {:error, gettext("AWS SES is busy — try again in a moment")}

      # The credentials are valid and merely lack `ses:GetSendQuota` — which is
      # exactly what AWS's own least-privilege guidance produces (grant only
      # ses:SendEmail / ses:SendRawEmail). Reporting "invalid credentials" here
      # would put a permanent red cross on a correctly configured integration and
      # teach operators to ignore the check.
      #
      # But this is NOT proof that the key can send: a signature valid for the
      # wrong AWS account also lands here. So it passes with the truth attached
      # rather than a bare green tick — the note reaches the operator, not just
      # the log.
      "AccessDenied" <> _ ->
        {:ok,
         gettext(
           "Credentials are valid, but not authorised for GetSendQuota — sending was not verified"
         )}

      nil ->
        {:error, gettext("Could not reach AWS SES")}

      code ->
        {:error, gettext("AWS SES error: %{code}", code: code)}
    end
  end

  def interpret_ses_error(_reason), do: {:error, gettext("Could not reach AWS SES")}

  # The Query API answers with an XML body carrying an <Code> element.
  defp aws_error_code(%{body: body}) when is_binary(body), do: aws_error_code(body)

  defp aws_error_code(body) when is_binary(body) do
    case Regex.run(~r{<Code>([^<]+)</Code>}, body) do
      [_, code] -> code
      _ -> nil
    end
  end

  defp aws_error_code(_), do: nil

  @doc false
  # Pure: an XML GetSendQuota body in, a compact operator-facing note out (or
  # `nil` if the body doesn't have the shape we expect — the credentials are
  # still good, we just have nothing to add). Public so the parsing can be
  # tested against real SES bodies without a network round trip.
  def format_quota_note(body) when is_binary(body) do
    with max when not is_nil(max) <- quota_tag(body, "Max24HourSend"),
         sent when not is_nil(sent) <- quota_tag(body, "SentLast24Hours"),
         rate when not is_nil(rate) <- quota_tag(body, "MaxSendRate") do
      # -1 signifies an unlimited quota — AWS's own convention for accounts
      # with no daily cap.
      max_text = if max == -1.0, do: gettext("unlimited"), else: Number.format(round(max))

      gettext("Quota: %{sent} / %{max} sent last 24h · max %{rate}/s",
        sent: Number.format(round(sent)),
        max: max_text,
        rate: Number.format(round(rate))
      )
    else
      _ -> nil
    end
  end

  def format_quota_note(_body), do: nil

  defp quota_tag(body, tag) do
    with [_, value] <- Regex.run(~r{<#{tag}>([^<]+)</#{tag}>}, body),
         {float, _rest} <- Float.parse(value) do
      float
    else
      _ -> nil
    end
  end

  # --- Brevo ------------------------------------------------------------

  @doc """
  Validates a Brevo API key against the account endpoint, and reports the
  remaining credits.

  Brevo authenticates with a bare `api-key` header (no `Bearer` prefix), and
  `GET /v3/account` doubles as the cheapest authenticated call and the only
  one that tells the operator anything beyond "the key works" — the plan's
  remaining send credits, which is exactly what silently runs out mid-campaign.
  """
  @spec brevo_api(map()) :: :ok | {:ok, String.t()} | {:error, String.t()}
  def brevo_api(data) do
    api_key = data["api_key"]

    if blank?(api_key) do
      {:error, gettext("No credentials configured")}
    else
      request_account(api_key)
    end
  end

  defp request_account(api_key) do
    case Req.get("https://api.brevo.com/v3/account",
           headers: [{"api-key", api_key}],
           receive_timeout: @http_timeout
         ) do
      {:ok, %{status: 200, body: body}} ->
        case format_credits_note(body) do
          nil -> :ok
          note -> {:ok, note}
        end

      {:ok, %{status: 401}} ->
        {:error, gettext("Invalid credentials")}

      {:ok, %{status: 403}} ->
        {:error, gettext("Access denied")}

      {:ok, %{status: status}} ->
        {:error, gettext("Brevo error %{status}", status: status)}

      {:error, reason} ->
        Logger.warning("Brevo connection check failed: #{inspect(reason)}")
        {:error, gettext("Could not reach Brevo")}
    end
  end

  @doc false
  # Pure: a decoded /v3/account JSON body in, a compact operator-facing note
  # out (or `nil` if there is no usable plan info). Public so the parsing can
  # be tested against real Brevo bodies without a network round trip.
  def format_credits_note(%{"plan" => plan}) when is_list(plan) and plan != [] do
    case plan |> Enum.map(&format_plan_entry/1) |> Enum.reject(&is_nil/1) do
      [] -> nil
      entries -> gettext("Plan: %{entries}", entries: Enum.join(entries, "; "))
    end
  end

  def format_credits_note(_body), do: nil

  defp format_plan_entry(%{"type" => type} = entry) when is_binary(type) do
    entry
    |> Map.get("credits")
    |> credits_text(type)
    |> with_reset_date(entry["endDate"])
  end

  defp format_plan_entry(_entry), do: nil

  defp credits_text(credits, type) when is_number(credits) do
    gettext("%{type} · %{credits} credits left",
      type: type,
      credits: Number.format(round(credits))
    )
  end

  defp credits_text(_credits, type), do: type

  defp with_reset_date(text, end_date) do
    case reset_date(end_date) do
      nil -> text
      date -> gettext("%{text} · resets %{date}", text: text, date: date)
    end
  end

  # Brevo's real /v3/account sends `endDate` as an ISO-8601 STRING
  # ("2017-04-11T00:00:00.000Z" — confirmed against the official reference,
  # Postman collection and SDKs). The integer clause is belt-and-braces for
  # a unix timestamp, should the API ever change shape.
  defp reset_date(end_date) when is_binary(end_date) do
    case DateTime.from_iso8601(end_date) do
      {:ok, datetime, _offset} -> Date.to_iso8601(DateTime.to_date(datetime))
      {:error, _reason} -> nil
    end
  end

  defp reset_date(end_date) when is_integer(end_date) do
    case DateTime.from_unix(end_date) do
      {:ok, datetime} -> Date.to_iso8601(DateTime.to_date(datetime))
      {:error, _reason} -> nil
    end
  end

  defp reset_date(_end_date), do: nil

  # --- Telegram ---------------------------------------------------------

  @doc """
  Validates a Telegram bot token against the Bot API's `getMe`.

  Telegram embeds the token in the URL path (`/bot<token>/getMe`) rather than a
  header, so it can't use the generic header-based check. `getMe` is the
  cheapest authenticated call, and its reply carries the bot's username — a
  useful confirmation the operator connected the bot they meant to.
  """
  @spec telegram(map()) :: :ok | {:ok, String.t()} | {:error, String.t()}
  def telegram(data) do
    token = data["bot_token"]

    if blank?(token) do
      {:error, gettext("No bot token configured")}
    else
      request_telegram(token)
    end
  end

  defp request_telegram(token) do
    case Req.get("https://api.telegram.org/bot#{token}/getMe", receive_timeout: @http_timeout) do
      {:ok, %{status: 200, body: body}} ->
        case telegram_username(body) do
          nil -> :ok
          username -> {:ok, gettext("Connected as @%{username}", username: username)}
        end

      # Telegram answers a bad or malformed token with 401/404 on this path.
      {:ok, %{status: status}} when status in [401, 404] ->
        {:error, gettext("Invalid bot token")}

      {:ok, %{status: status}} ->
        {:error, gettext("Telegram error %{status}", status: status)}

      {:error, reason} ->
        Logger.warning("Telegram connection check failed: #{inspect(reason)}")
        {:error, gettext("Could not reach Telegram")}
    end
  end

  defp telegram_username(%{"ok" => true, "result" => %{"username" => username}})
       when is_binary(username) and username != "",
       do: username

  defp telegram_username(_body), do: nil

  # --- shared ---------------------------------------------------------------

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false
end
