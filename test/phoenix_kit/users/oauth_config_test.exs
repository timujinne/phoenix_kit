defmodule PhoenixKit.Users.OAuthConfigTest do
  @moduledoc """
  Covers the "Test Credentials" button fix (dev_docs I135): the button used
  to check only that a field was non-empty (`value == ""`), so a whitespace
  value or a 9-character secret both read as "properly formatted" — Google
  itself answered the same values with 401 invalid_client.

  These tests exercise the pieces that do NOT require a live network round
  trip or a database: `validate_secret_format/2` and `test_connection/2`'s
  fast pre-checks (which reject before ever calling out to a provider), plus
  `interpret_google_token_response/1`, the pure classifier behind the real
  Google check, fed synthetic Req-response-shaped tuples. The live Google
  round trip itself is exercised manually — see the I135 report for the
  transcript — not here, because a real call to `oauth2.googleapis.com` is
  network-dependent and (confirmed live) not perfectly deterministic: Google
  can answer a well-formed request with a generic anti-abuse page instead of
  a clean invalid_client/invalid_grant, which is exactly the "inconclusive"
  branch `interpret_google_token_response/1` is tested against below.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Users.OAuthConfig

  describe "validate_secret_format/2" do
    test "blank (nil or empty string) is allowed — OAuth is opt-in per provider" do
      assert OAuthConfig.validate_secret_format(:google, nil) == :ok
      assert OAuthConfig.validate_secret_format(:google, "") == :ok
    end

    test "whitespace-only is rejected, not silently treated as blank" do
      assert {:error, message} = OAuthConfig.validate_secret_format(:google, "    ")
      assert message =~ "whitespace"
    end

    test "the reported defect: a 9-character secret is rejected" do
      assert {:error, message} = OAuthConfig.validate_secret_format(:google, "123456789")
      assert message =~ "too short"
      assert message =~ "9 characters"
    end

    test "a plausible-length secret passes for all three providers" do
      long_secret = String.duplicate("a", 24)
      assert OAuthConfig.validate_secret_format(:google, long_secret) == :ok
      assert OAuthConfig.validate_secret_format(:github, long_secret) == :ok
      assert OAuthConfig.validate_secret_format(:facebook, long_secret) == :ok
    end

    test "leading/trailing whitespace around an otherwise-real secret does not itself fail" do
      long_secret = "  " <> String.duplicate("a", 24) <> "  "
      assert OAuthConfig.validate_secret_format(:google, long_secret) == :ok
    end
  end

  describe "test_connection/2 — fast rejections (no network call)" do
    test "missing fields are reported without contacting any provider" do
      assert {:error, message} =
               OAuthConfig.test_connection(:google, %{client_id: "", client_secret: ""})

      assert message =~ "Missing"
    end

    test "a whitespace-only field is treated as missing, not as a valid value" do
      assert {:error, message} =
               OAuthConfig.test_connection(:google, %{client_id: "x", client_secret: "   "})

      assert message =~ "Missing"
    end

    test "the reported defect via the button path: a 9-character Google secret is rejected fast" do
      {elapsed_us, result} =
        :timer.tc(fn ->
          OAuthConfig.test_connection(:google, %{
            client_id: "some-id.apps.googleusercontent.com",
            client_secret: "123456789"
          })
        end)

      assert {:error, message} = result
      assert message =~ "too short"
      # Rejected by the format check before ever reaching the network —
      # generous bound, but a real HTTPS round trip would not land under 1s.
      assert elapsed_us < 1_000_000
    end

    test "GitHub: a plausible-length pair is accepted (format-only, no live check for this provider)" do
      assert {:ok, message} =
               OAuthConfig.test_connection(:github, %{
                 client_id: String.duplicate("a", 20),
                 client_secret: String.duplicate("b", 40)
               })

      assert message =~ "GitHub"
      assert message =~ "properly formatted"
    end

    test "GitHub: the same short secret defect is rejected here too" do
      assert {:error, message} =
               OAuthConfig.test_connection(:github, %{
                 client_id: "some-client-id",
                 client_secret: "short"
               })

      assert message =~ "too short"
    end

    test "Facebook: a plausible-length pair is accepted (format-only, no live check for this provider)" do
      assert {:ok, message} =
               OAuthConfig.test_connection(:facebook, %{
                 app_id: "1234567890123456",
                 app_secret: String.duplicate("c", 32)
               })

      assert message =~ "Facebook"
      assert message =~ "properly formatted"
    end

    test "Facebook: the same short secret defect is rejected here too" do
      assert {:error, message} =
               OAuthConfig.test_connection(:facebook, %{
                 app_id: "1234567890123456",
                 app_secret: "short"
               })

      assert message =~ "too short"
    end
  end

  describe "interpret_google_token_response/1 — the three outcomes, pure (no network)" do
    test "invalid_client is a rejection" do
      response = {:ok, %{status: 401, body: %{"error" => "invalid_client"}}}
      assert {:error, message} = OAuthConfig.interpret_google_token_response(response)
      assert message =~ "invalid_client"
    end

    test "invalid_grant is an acceptance — the client authenticated, only the fake code failed" do
      response = {:ok, %{status: 400, body: %{"error" => "invalid_grant"}}}
      assert {:ok, message} = OAuthConfig.interpret_google_token_response(response)
      assert message =~ "accepted"
    end

    test "a transport failure is neither an accept nor a reject — it is 'could not reach'" do
      response = {:error, %Req.TransportError{reason: :nxdomain}}
      assert {:error, message} = OAuthConfig.interpret_google_token_response(response)
      assert message =~ "reach"
      refute message =~ "invalid_client"
    end

    # Confirmed live (I135 report): Google's own anti-abuse front door can
    # answer a well-formed request with "invalid_request" instead of a real
    # invalid_client/invalid_grant verdict — this must not be misread as
    # either.
    test "an unrecognized error code is inconclusive, not silently accepted or rejected" do
      response = {:ok, %{status: 400, body: %{"error" => "invalid_request"}}}
      assert {:error, message} = OAuthConfig.interpret_google_token_response(response)
      assert message =~ "inconclusive"
      refute message =~ "invalid_client"
    end

    test "a response with no recognizable error field is inconclusive" do
      response = {:ok, %{status: 500, body: %{}}}
      assert {:error, message} = OAuthConfig.interpret_google_token_response(response)
      assert message =~ "inconclusive"
    end
  end
end
