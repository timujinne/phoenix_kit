defmodule PhoenixKit.Utils.SessionFingerprintLoggingTest do
  @moduledoc """
  What the fingerprint check writes to the log.

  One reporting app carried **765** `user_agent_mismatch` warnings, plus
  `[error] ... possible hijacking attempt` lines after which — in non-strict
  mode — the request was served anyway. Two lines per request, per-request and
  unthrottled, naming neither the user nor the session.

  That is worse than logging nothing: an error that takes no action and names
  no one teaches people the log is noise, and the lines that would have
  mattered go with it. So the levels have to mean something, and each line has
  to say which session it is about.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Utils.SessionFingerprint

  @stored_ip "203.0.113.7"
  @other_ip "198.51.100.9"

  setup do
    # This suite runs at `level: :warning`, which is the point — the
    # user-agent line is demoted precisely so a normally-configured app never
    # sees it. Lowered here so the assertions can tell "logged at info" apart
    # from "not logged", which are the same thing from the outside.
    previous = Logger.level()
    Logger.configure(level: :info)
    on_exit(fn -> Logger.configure(level: previous) end)
    :ok
  end

  defp conn(ip, user_agent) do
    :get
    |> Plug.Test.conn("/")
    |> Plug.Conn.put_req_header("x-forwarded-for", ip)
    |> Plug.Conn.put_req_header("user-agent", user_agent)
  end

  defp stored_ua_hash(user_agent),
    do: SessionFingerprint.hash_user_agent(conn(@stored_ip, user_agent))

  defp verify(conn, opts \\ []) do
    stored = stored_ua_hash("Mozilla/5.0 original")

    capture_log([level: :info], fn ->
      SessionFingerprint.verify_fingerprint(conn, @stored_ip, stored, opts)
    end)
  end

  describe "a browser that updated itself" do
    test "is not a warning" do
      # Browsers rewrite their user agent roughly monthly, for every user. At
      # warning level this was the bulk of the log, for something that is
      # almost never an attack and is never acted on.
      log = verify(conn(@stored_ip, "Mozilla/5.0 updated"))

      refute log =~ "[warning]"
      refute log =~ "[error]"
      assert log =~ "changed user agent"
    end
  end

  describe "a session that moved" do
    test "IP change stays a warning" do
      log = verify(conn(@other_ip, "Mozilla/5.0 original"))

      assert log =~ "[warning]"
      assert log =~ "changed IP"
    end
  end

  describe "both changed" do
    setup do
      original = Application.get_env(:phoenix_kit, :session_fingerprint_strict)
      on_exit(fn -> Application.put_env(:phoenix_kit, :session_fingerprint_strict, original) end)
      :ok
    end

    test "is an error only when it actually denies the request" do
      # Strict mode refuses the request, so :error is the truth.
      Application.put_env(:phoenix_kit, :session_fingerprint_strict, true)
      log = verify(conn(@other_ip, "Mozilla/5.0 different"))

      assert log =~ "[error]"
      assert log =~ "denied"
    end

    test "is a warning when the request is served anyway" do
      # This is the line that trained people to ignore the log: "possible
      # hijacking attempt", logged at :error, followed by serving the request.
      Application.put_env(:phoenix_kit, :session_fingerprint_strict, false)
      log = verify(conn(@other_ip, "Mozilla/5.0 different"))

      refute log =~ "[error]"
      assert log =~ "[warning]"
      assert log =~ "allowed"
    end
  end

  describe "strict mode denies every mismatch, so every line is an error" do
    # The level-follows-consequence rule applied to one branch of three.
    # Strict mode refuses the request for an IP-only and a user-agent-only
    # change too — `PhoenixKitWeb.Users.Auth` answers `{:warning, _}` with
    # `not strict_mode?()` exactly as it answers `{:error, _}` — so an
    # operator working out why a user was logged out over a browser update
    # was reading an :info line to find it.
    setup do
      original = Application.get_env(:phoenix_kit, :session_fingerprint_strict)
      Application.put_env(:phoenix_kit, :session_fingerprint_strict, true)
      on_exit(fn -> Application.put_env(:phoenix_kit, :session_fingerprint_strict, original) end)
      :ok
    end

    test "a user-agent change that logs someone out is not an :info line" do
      log = verify(conn(@stored_ip, "Mozilla/5.0 updated"))

      assert log =~ "[error]"
      assert log =~ "denied"
      assert log =~ "changed user agent"
    end

    test "an IP change that logs someone out is not a mere warning" do
      log = verify(conn(@other_ip, "Mozilla/5.0 original"))

      assert log =~ "[error]"
      assert log =~ "denied"
      assert log =~ "changed IP"
    end
  end

  describe "correlation" do
    test "every line names the session it is about" do
      for c <- [conn(@other_ip, "Mozilla/5.0 original"), conn(@stored_ip, "Mozilla/5.0 new")] do
        assert verify(c, session: "a1b2c3d4") =~ "a1b2c3d4"
      end
    end

    test "a caller that gives no label still logs" do
      # Degrades to an unlabelled line rather than crashing the request it was
      # only ever meant to describe.
      assert verify(conn(@other_ip, "Mozilla/5.0 original")) =~ "changed IP"
    end
  end

  describe "a matching fingerprint" do
    test "says nothing at all" do
      assert verify(conn(@stored_ip, "Mozilla/5.0 original")) == ""
    end
  end
end
