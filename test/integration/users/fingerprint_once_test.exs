defmodule PhoenixKit.Integration.Users.FingerprintOnceTest do
  @moduledoc """
  The session fingerprint is verified at most once per request, and its
  label matches the sessions UI.

  The shipped `:phoenix_kit_admin_only` pipeline runs BOTH fetch plugs
  (`fetch_phoenix_kit_current_user` and `fetch_phoenix_kit_current_scope`),
  and each used to verify — and therefore log — independently: every
  mismatch was checked twice, logged up to three times, including a leftover
  `:error` "possible hijacking" line for requests that were then served.
  Verification now runs once, its verdict cached in `conn.private`, and the
  second plug reuses it.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Users.Auth
  alias PhoenixKitWeb.Users.Auth, as: AuthPlugs

  defp user_and_token do
    {:ok, user} =
      Auth.register_user(%{
        email: "fp_once_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    {user, Auth.generate_user_session_token(user)}
  end

  defp conn_with_token(token) do
    :get
    |> Plug.Test.conn("/")
    |> Plug.Test.init_test_session(%{"user_token" => token})
  end

  describe "the cached verdict is authoritative" do
    # The proof that verification happens at most once: pre-seed the cache
    # with the OPPOSITE of what a fresh verification would return. If either
    # plug re-verified, it would overturn the seeded verdict and load the
    # user anyway — fingerprinting is off in this suite, so a fresh check
    # answers :ok.
    test "a cached denial is honored by both plugs without re-verifying" do
      {_user, token} = user_and_token()

      conn =
        token
        |> conn_with_token()
        |> Plug.Conn.put_private(:phoenix_kit_fingerprint_valid, false)

      conn = AuthPlugs.fetch_phoenix_kit_current_user(conn, [])
      assert conn.assigns.phoenix_kit_current_user == nil

      conn = AuthPlugs.fetch_phoenix_kit_current_scope(conn, [])
      assert conn.assigns.phoenix_kit_current_scope.user == nil
    end

    test "the first plug caches its verdict for the second" do
      {user, token} = user_and_token()

      conn = AuthPlugs.fetch_phoenix_kit_current_user(conn_with_token(token), [])

      assert conn.private[:phoenix_kit_fingerprint_valid] == true
      assert conn.assigns.phoenix_kit_current_user.uuid == user.uuid

      conn = AuthPlugs.fetch_phoenix_kit_current_scope(conn, [])
      assert conn.assigns.phoenix_kit_current_scope.user.uuid == user.uuid
    end

    test "a conn with no session token skips the machinery entirely" do
      conn =
        :get
        |> Plug.Test.conn("/")
        |> Plug.Test.init_test_session(%{})
        |> AuthPlugs.fetch_phoenix_kit_current_user([])

      assert conn.assigns.phoenix_kit_current_user == nil
      refute Map.has_key?(conn.private, :phoenix_kit_fingerprint_valid)
    end
  end

  describe "session_label/1" do
    test "matches the sessions UI's token preview, so the correlation works" do
      # The label exists to be pasted into the sessions page search. The UI
      # shows `encode(substring(token, 1, 4), 'hex')`; the previous label
      # (truncated sha256) could never match it — an operator searching for
      # a logged label got zero results every time.
      {_user, token} = user_and_token()

      ui_preview = token |> binary_part(0, 4) |> Base.encode16(case: :lower)

      assert Auth.session_label(token) == ui_preview
      assert String.length(Auth.session_label(token)) == 8
    end

    test "degrades to a placeholder rather than crashing on junk" do
      assert Auth.session_label(nil) == "unknown"
      assert Auth.session_label("ab") == "unknown"
    end
  end
end
