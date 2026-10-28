defmodule PhoenixKit.API.CredentialRedactionTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Idempotency

  test "approval storage uses the replay credential rules throughout nested JSON" do
    for key <-
          ~w(session_token confirm_token claim_token api_key access_token token secret) do
      value = %{"partial" => [%{"done" => 1, String.upcase(key) => "sensitive"}]}
      assert Idempotency.credential_bearing?(JSON.encode!(value))

      assert Idempotency.redact_credentials(value) ==
               %{"partial" => [%{"done" => 1, String.upcase(key) => "[REDACTED]"}]}
    end

    assert Idempotency.redact_credentials(%{
             "rows" => ["pk_secret", "ordinary"],
             "count" => 2,
             "ok" => true
           }) == %{"rows" => ["[REDACTED]", "ordinary"], "count" => 2, "ok" => true}
  end

  test "an output field the tool declares as a credential is redacted, and only for that tool" do
    value = %{"url" => "https://example.test/x", "nested" => [%{"URL" => "y", "ok" => 1}]}

    assert Idempotency.redact_credentials(value) == value

    assert Idempotency.redact_credentials(value, ["url"]) ==
             %{"url" => "[REDACTED]", "nested" => [%{"URL" => "[REDACTED]", "ok" => 1}]}
  end

  test "any name ending in _token is redacted, a lookalike is not" do
    assert Idempotency.redact_credentials(%{
             "page_token" => "a",
             "token_count" => 3,
             "tokens" => 2
           }) ==
             %{"page_token" => "[REDACTED]", "token_count" => 3, "tokens" => 2}
  end
end
