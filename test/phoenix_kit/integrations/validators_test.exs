defmodule PhoenixKit.Integrations.ValidatorsTest do
  # async: false — one test swaps the global check deadline.
  use ExUnit.Case, async: false

  alias PhoenixKit.Integrations.Validators

  describe "aws_ses/1 refuses to guess" do
    test "a blank region is an error, not a silent probe of us-east-1" do
      # ExAws defaults a missing region to us-east-1, so without this guard the
      # check would pass against the wrong account/region while the send path
      # (which interpolates the region into the hostname) raises at send time.
      creds = %{"access_key" => "AKIA_T", "secret_key" => "S", "aws_region" => ""}
      assert {:error, message} = Validators.aws_ses(creds)
      assert message =~ "Region"
    end

    test "missing keys are reported without a network round trip" do
      assert {:error, _} = Validators.aws_ses(%{"aws_region" => "eu-central-1"})
    end
  end

  # AWS briefly answers a *correct* request with SignatureDoesNotMatch right after it
  # has rejected a bad signature from the same key — which is exactly what an operator
  # produces by pasting a wrong key, fixing it, and pressing Test again. Telling them
  # their good keys are invalid sends them off to reissue credentials that were never
  # the problem, so a verdict of "invalid" is confirmed before it is delivered.
  describe "the invalid-credentials verdict is confirmed before it is delivered" do
    test "a key that fails once and then succeeds is NOT called invalid" do
      requester = stub([{:invalid, "SignatureDoesNotMatch"}, :ok])

      assert :ok == Validators.request_send_quota("eu-central-1", %{}, requester)
    end

    test "a key that fails twice is called invalid" do
      requester = stub([{:invalid, "SignatureDoesNotMatch"}, {:invalid, "SignatureDoesNotMatch"}])

      assert {:error, message} = Validators.request_send_quota("eu-central-1", %{}, requester)
      assert message =~ "Invalid credentials"
    end

    test "a key that works is not retried" do
      requester = stub([:ok, {:invalid, "should never be asked for"}])

      assert :ok == Validators.request_send_quota("eu-central-1", %{}, requester)
    end

    test "a non-credential error is returned as-is, without a retry" do
      requester = stub([{:error, "AWS SES is busy"}, :ok])

      assert {:error, "AWS SES is busy"} =
               Validators.request_send_quota("eu-central-1", %{}, requester)
    end
  end

  describe "interpret_ses_error/1" do
    test "signature and token failures mean the credentials are wrong" do
      for code <- ~w(SignatureDoesNotMatch InvalidClientTokenId UnrecognizedClientException
                     InvalidAccessKeyId ExpiredToken TokenRefreshRequired) do
        assert {:invalid, ^code} = Validators.interpret_ses_error(aws_error(code))
      end
    end

    test "AccessDenied passes, but says what it could not verify" do
      # AWS's own least-privilege guidance grants only ses:SendEmail, which cannot call
      # GetSendQuota — so a red cross here would sit permanently on a correctly
      # configured integration and teach operators to ignore the check. But it is not
      # proof that the key can send: a signature valid for the WRONG AWS account lands
      # here too. So it passes with the caveat attached, and the caveat reaches the
      # operator rather than the log.
      assert {:ok, note} = Validators.interpret_ses_error(aws_error("AccessDenied"))
      assert note =~ "not authorised"
      assert note =~ "sending was not verified"

      assert {:ok, _} = Validators.interpret_ses_error(aws_error("AccessDeniedException"))
    end

    test "throttling says so instead of blaming the credentials" do
      assert {:error, message} = Validators.interpret_ses_error(aws_error("Throttling"))
      assert message =~ "busy"
    end

    test "an unrecognised code is surfaced verbatim rather than guessed at" do
      assert {:error, message} = Validators.interpret_ses_error(aws_error("MessageRejected"))
      assert message =~ "MessageRejected"
    end

    test "a body with no code, and anything that is not an HTTP error, are transport failures" do
      assert {:error, message} =
               Validators.interpret_ses_error({:http_error, 500, %{body: "<html>502</html>"}})

      assert message =~ "Could not reach"
      assert {:error, _} = Validators.interpret_ses_error(:timeout)
    end
  end

  describe "format_quota_note/1" do
    test "reports sent/max/rate from a real GetSendQuota body" do
      body = quota_body(max: "50000.0", sent: "127.0", rate: "14.0")

      assert note = Validators.format_quota_note(body)
      assert note =~ "127"
      assert note =~ "50,000"
      assert note =~ "14"
    end

    test "large numbers get thousand separators" do
      body = quota_body(max: "1000000.0", sent: "1234.0", rate: "50.0")

      note = Validators.format_quota_note(body)
      assert note =~ "1,234"
      assert note =~ "1,000,000"
    end

    # AWS's own convention: -1 means the account has no daily cap, rather than
    # a cap of negative-one messages.
    test "a Max24HourSend of -1 reads as unlimited, not -1" do
      body = quota_body(max: "-1.0", sent: "42.0", rate: "14.0")

      note = Validators.format_quota_note(body)
      assert note =~ "unlimited"
      refute note =~ "-1"
    end

    test "a body missing one of the three fields yields no note" do
      body = """
      <GetSendQuotaResponse><GetSendQuotaResult>
        <Max24HourSend>50000.0</Max24HourSend>
        <MaxSendRate>14.0</MaxSendRate>
      </GetSendQuotaResult></GetSendQuotaResponse>
      """

      assert Validators.format_quota_note(body) == nil
    end

    test "not a string at all yields no note rather than a crash" do
      assert Validators.format_quota_note(%{}) == nil
      assert Validators.format_quota_note(nil) == nil
    end

    defp quota_body(opts) do
      max = Keyword.fetch!(opts, :max)
      sent = Keyword.fetch!(opts, :sent)
      rate = Keyword.fetch!(opts, :rate)

      """
      <GetSendQuotaResponse xmlns="http://ses.amazonaws.com/doc/2010-12-01/">
        <GetSendQuotaResult>
          <Max24HourSend>#{max}</Max24HourSend>
          <MaxSendRate>#{rate}</MaxSendRate>
          <SentLast24Hours>#{sent}</SentLast24Hours>
        </GetSendQuotaResult>
        <ResponseMetadata><RequestId>abc</RequestId></ResponseMetadata>
      </GetSendQuotaResponse>
      """
    end
  end

  describe "format_credits_note/1" do
    test "a single subscription plan reports its type and credits" do
      body = %{
        "plan" => [%{"type" => "subscription", "creditsType" => "sendLimit", "credits" => 8500}]
      }

      assert note = Validators.format_credits_note(body)
      assert note =~ "subscription"
      assert note =~ "8,500 credits left"
    end

    test "multiple plan entries are all reported" do
      body = %{
        "plan" => [
          %{"type" => "subscription", "creditsType" => "sendLimit", "credits" => 8500},
          %{"type" => "payAsYouGo", "creditsType" => "sendLimit", "credits" => 120}
        ]
      }

      note = Validators.format_credits_note(body)
      assert note =~ "subscription"
      assert note =~ "8,500"
      assert note =~ "payAsYouGo"
      assert note =~ "120"
    end

    test "a plan entry with no credits key still names the plan type" do
      body = %{"plan" => [%{"type" => "free", "creditsType" => "sendLimit"}]}

      assert note = Validators.format_credits_note(body)
      assert note =~ "free"
      refute note =~ "credits left"
    end

    test "an endDate is surfaced as a reset date" do
      # Brevo's REAL wire shape: endDate is an ISO-8601 string, not a unix
      # integer (verified against the official reference and Postman
      # collection). The integer variant below is the belt-and-braces path.
      body = %{
        "plan" => [
          %{
            "type" => "subscription",
            "creditsType" => "sendLimit",
            "credits" => 8500,
            "endDate" => "2026-08-01T00:00:00.000Z"
          }
        ]
      }

      assert note = Validators.format_credits_note(body)
      assert note =~ "2026-08-01"
    end

    test "a unix-integer endDate is also accepted (defensive)" do
      # 2026-08-01T00:00:00Z
      body = %{
        "plan" => [
          %{
            "type" => "subscription",
            "credits" => 8500,
            "endDate" => 1_785_542_400
          }
        ]
      }

      assert note = Validators.format_credits_note(body)
      assert note =~ "2026-08-01"
    end

    test "an unparseable endDate is dropped, not crashed on" do
      body = %{
        "plan" => [
          %{"type" => "subscription", "credits" => 8500, "endDate" => "soon"}
        ]
      }

      assert note = Validators.format_credits_note(body)
      refute note =~ "resets"
    end

    test "no endDate means no reset date is claimed" do
      body = %{
        "plan" => [%{"type" => "subscription", "creditsType" => "sendLimit", "credits" => 8500}]
      }

      note = Validators.format_credits_note(body)
      refute note =~ "resets"
    end

    test "an empty or missing plan yields no note" do
      assert Validators.format_credits_note(%{"plan" => []}) == nil
      assert Validators.format_credits_note(%{}) == nil
      assert Validators.format_credits_note(%{"plan" => "not a list"}) == nil
    end
  end

  describe "smtp/1" do
    test "an unreachable relay is rejected" do
      # Nothing listens on port 1 — fails immediately, no outside network needed.
      creds = %{"host" => "127.0.0.1", "port" => "1", "username" => "u", "password" => "p"}
      assert {:error, _reason} = Validators.smtp(creds)
    end

    test "a malformed setting is reported instead of raising out of the LiveView" do
      # These translations sit OUTSIDE Probe.run and its rescue, so an unmatched
      # reason would surface as a CaseClauseError in the caller's callback.
      base = %{"host" => "127.0.0.1", "port" => "587", "username" => "u", "password" => "p"}

      assert {:error, security} = Validators.smtp(Map.put(base, "security", "tls-please"))
      assert security =~ "security"

      assert {:error, verify} = Validators.smtp(Map.put(base, "verify_cert", "sometimes"))
      assert verify =~ "verify_cert"

      assert {:error, auth} = Validators.smtp(Map.put(base, "auth", "maybe"))
      assert auth =~ "auth"

      assert {:error, timeout} = Validators.smtp(Map.put(base, "timeout", "soon"))
      assert timeout =~ "timeout" or timeout =~ "Timeout"

      assert {:error, ca} = Validators.smtp(Map.put(base, "ca_cert", "not a certificate"))
      assert ca =~ "PEM" or ca =~ "certificate"
    end

    test "an unparseable port is reported as such" do
      creds = %{"host" => "127.0.0.1", "port" => "nope", "username" => "u", "password" => "p"}
      assert {:error, message} = Validators.smtp(creds)
      assert message =~ "port"
    end

    test "a relay that advertises no AUTH verb passes" do
      # An internal smarthost that authenticates by IP. Sending works there, so a red
      # cross would be a lie about a working relay — and the operator could not avoid
      # it, since username/password are required fields. `auth: :always` is what makes
      # a *wrong password* fail closed, so the no-AUTH case is carved out rather than
      # weakening it.
      port = relay_without_auth()

      creds = %{"host" => "127.0.0.1", "port" => port, "username" => "", "password" => ""}

      assert :ok == Validators.smtp(creds)
    end

    test "a tarpit relay is cut off at the deadline instead of hanging the caller" do
      # gen_smtp bounds only the TCP connect; every read after it waits on a
      # hard-coded 20-minute timeout, in the CALLING process. Both call sites are
      # LiveView callbacks, so without an outer deadline one silent relay parks a
      # LiveView process for twenty minutes.
      port = silent_relay()

      Application.put_env(:phoenix_kit, :integration_check_deadline, 300)
      on_exit(fn -> Application.delete_env(:phoenix_kit, :integration_check_deadline) end)

      creds = %{"host" => "127.0.0.1", "port" => port, "username" => "u", "password" => "p"}

      {elapsed_us, result} = :timer.tc(fn -> Validators.smtp(creds) end)

      assert {:error, message} = result
      assert message =~ "did not respond"
      # Comfortably under gen_smtp's own 20-minute read timeout.
      assert elapsed_us < 5_000_000
    end
  end

  # --- helpers ---------------------------------------------------------------

  # Answers the given results in order. A plain closure beats a mocking library here:
  # the thing under test is "how many times is AWS asked, and what is done with each
  # answer", which is exactly what a queue makes visible.

  describe "amazon_bedrock/1 refuses to guess" do
    test "missing key and missing region are reported without a network round trip" do
      assert {:error, _} = Validators.amazon_bedrock(%{"aws_region" => "eu-central-1"})
      assert {:error, message} = Validators.amazon_bedrock(%{"api_key" => "ABSK_T"})
      assert message =~ "Region"
    end

    test "a malformed region is rejected before it becomes a hostname" do
      for bad <- ["eu central", "EU-CENTRAL-1", "bedrock.evil.example/", "eu-central-"] do
        creds = %{"api_key" => "ABSK_T", "aws_region" => bad}
        assert {:error, message} = Validators.amazon_bedrock(creds)
        assert message =~ "region format"
      end
    end

    test "real region shapes pass the format guard, including 4-letter sovereign prefixes" do
      for good <- [
            "us-east-1",
            "ap-southeast-3",
            "il-central-1",
            "us-gov-west-1",
            "eusc-de-east-1"
          ] do
        assert Validators.valid_aws_region?(good), good
      end

      for bad <- ["", "eu central", "EU-CENTRAL-1", "bedrock.evil.example/", "eu-central-", nil] do
        refute Validators.valid_aws_region?(bad), inspect(bad)
      end
    end
  end

  describe "aws_note/3 assembles the enrichment note additively" do
    test "lists only GRANTED management APIs — a send-only key shows no denied dashes" do
      perms = %{
        ses: %{"ListConfigurationSets" => :denied},
        sqs: %{"ListQueues" => :denied},
        sns: %{"ListTopics" => :denied}
      }

      assert Validators.aws_note("Account 1", perms, nil) == "Account 1"
    end

    test "grants surface by service name" do
      perms = %{
        ses: %{"ListConfigurationSets" => :granted},
        sqs: %{"ListQueues" => :granted},
        sns: %{"ListTopics" => :denied}
      }

      note = Validators.aws_note("Account 1", perms, "Quota: 1/200")
      assert note =~ "SES, SQS"
      refute note =~ "SNS"
      assert note =~ "Quota: 1/200"
    end

    test "nothing to say means nil, so the verdict stays a bare :ok" do
      assert Validators.aws_note(nil, nil, nil) == nil
    end

    test "a missing permissions sweep keeps identity and quota" do
      assert Validators.aws_note("Account 1", nil, "Q") == "Account 1 · Q"
    end

    test "a partial permissions map is read, not crashed on" do
      assert Validators.aws_note(nil, %{ses: %{"ListConfigurationSets" => :granted}}, nil) =~
               "SES"
    end
  end

  describe "bedrock_host/1 follows the partition" do
    test "the China partition gets its own suffix" do
      assert Validators.bedrock_host("cn-north-1") =~ ".amazonaws.com.cn"
      assert Validators.bedrock_host("eu-central-1") =~ ".amazonaws.com"
      refute Validators.bedrock_host("eu-central-1") =~ ".cn"
    end
  end

  defp stub(results) do
    {:ok, agent} = Agent.start_link(fn -> results end)
    on_exit(fn -> if Process.alive?(agent), do: Agent.stop(agent) end)

    fn _region, _data ->
      Agent.get_and_update(agent, fn
        [result | rest] -> {result, rest}
        [] -> raise "the requester was called more times than the test allows"
      end)
    end
  end

  # Accepts the connection and then says nothing at all — no SMTP banner.
  defp silent_relay do
    listener = listen()

    server =
      spawn(fn ->
        {:ok, _socket} = :gen_tcp.accept(listener)
        # Hold it open: an acceptor that exits closes the socket with it, and the
        # client would see a dropped connection rather than the silence under test.
        Process.sleep(:infinity)
      end)

    # spawn_link would NOT do: a normal exit does not propagate, so the acceptor, the
    # listener and the accepted socket would outlive the test for the life of the VM.
    reap(server, listener)
    port(listener)
  end

  # Greets, answers EHLO, and advertises no AUTH — an IP-authenticated smarthost.
  defp relay_without_auth do
    listener = listen()

    server =
      spawn(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        :gen_tcp.send(socket, "220 relay.internal ESMTP\r\n")
        {:ok, _ehlo} = :gen_tcp.recv(socket, 0, 5_000)
        :gen_tcp.send(socket, "250-relay.internal\r\n250-8BITMIME\r\n250 SIZE 10240000\r\n")
        # The client gives up at the auth step; hold the socket until we are reaped.
        Process.sleep(:infinity)
      end)

    reap(server, listener)
    port(listener)
  end

  defp listen do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, packet: :line])

    listener
  end

  defp port(listener) do
    {:ok, port} = :inet.port(listener)
    port
  end

  defp reap(server, listener) do
    on_exit(fn ->
      Process.exit(server, :kill)
      :gen_tcp.close(listener)
    end)
  end

  defp aws_error(code) do
    {:http_error, 403,
     %{
       body:
         "<ErrorResponse><Error><Code>#{code}</Code><Message>x</Message></Error></ErrorResponse>"
     }}
  end
end
