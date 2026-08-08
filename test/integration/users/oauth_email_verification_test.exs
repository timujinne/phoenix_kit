defmodule PhoenixKit.Integration.Users.OAuthEmailVerificationTest do
  @moduledoc """
  An OAuth callback must not attach an external identity to a pre-existing
  local account on email string equality alone: whoever gets an address onto a
  provider account then signs in as its owner. These tests pin the three
  resolution paths — existing link, existing local account, new account.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Setting.SettingsForm
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.UserToken
  alias PhoenixKit.Users.OAuth
  alias PhoenixKit.Users.OAuthProvider

  defp unique_email, do: "oauth_#{System.unique_integer([:positive])}@example.com"

  defp local_user(email) do
    {:ok, user} = Auth.register_user(%{email: email, password: "ValidPassword123!"})
    Repo.get!(Auth.User, user.uuid)
  end

  defp oauth_data(email, overrides \\ %{}) do
    Map.merge(
      %{
        provider: "google",
        provider_uid: "uid_#{System.unique_integer([:positive])}",
        email: email,
        first_name: "Test",
        last_name: "User",
        image: nil,
        access_token: "at",
        refresh_token: nil,
        token_expires_at: nil,
        raw_info: %{}
      },
      overrides
    )
  end

  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  describe "attaching to an existing local account" do
    test "is refused when the provider asserts nothing" do
      email = unique_email()
      _user = local_user(email)

      assert {:error, :provider_email_unverified} = OAuth.find_or_create_user(oauth_data(email))
    end

    test "is refused when the provider says the address is NOT verified" do
      email = unique_email()
      _user = local_user(email)

      data = oauth_data(email, %{raw_info: %{"user" => %{"email_verified" => false}}})

      assert {:error, :provider_email_unverified} = OAuth.find_or_create_user(data)
    end

    test "is allowed when the provider asserts email_verified, in the shape the strategies emit" do
      email = unique_email()
      user = local_user(email)

      # ueberauth_google/github/facebook all build
      # `raw_info: %{token: ..., user: ...}` with ATOM keys, and the payload
      # nested under `:user` is decoded JSON with STRING keys. A gate that reads
      # only `"user"` never fires on a real callback — this test is what pins
      # that down.
      data =
        oauth_data(email, %{
          raw_info: %{token: "tok", user: %{"email" => email, "email_verified" => true}}
        })

      assert {:ok, found, :found} = OAuth.find_or_create_user(data)
      assert found.uuid == user.uuid
    end

    test "accepts a string-keyed raw_info too, for providers that hand one over" do
      email = unique_email()
      _user = local_user(email)

      data = oauth_data(email, %{raw_info: %{"user" => %{"email_verified" => true}}})

      assert {:ok, _user, :found} = OAuth.find_or_create_user(data)
    end

    test "accepts the string spelling of the claim value providers sometimes send" do
      email = unique_email()
      _user = local_user(email)

      data = oauth_data(email, %{raw_info: %{user: %{"email_verified" => "true"}}})

      assert {:ok, _user, :found} = OAuth.find_or_create_user(data)
    end

    test "an OIDC provider that puts the claim at the top level of raw_info" do
      email = unique_email()
      _user = local_user(email)

      data = oauth_data(email, %{raw_info: %{email_verified: true}})

      assert {:ok, _user, :found} = OAuth.find_or_create_user(data)
    end

    test "GitHub: the verified flag must belong to THIS address" do
      email = unique_email()
      _user = local_user(email)

      matching =
        oauth_data(email, %{
          provider: "github",
          raw_info: %{user: %{"emails" => [%{"email" => email, "verified" => true}]}}
        })

      assert {:ok, _user, :found} = OAuth.find_or_create_user(matching)

      other_address =
        oauth_data(email, %{
          provider: "github",
          raw_info: %{
            user: %{
              "emails" => [
                %{"email" => "someone-else@example.com", "verified" => true},
                %{"email" => email, "verified" => false}
              ]
            }
          }
        })

      assert {:error, :provider_email_unverified} = OAuth.find_or_create_user(other_address)
    end

    test "GitHub as the strategy actually delivers it when the token lacks the email scope" do
      # With `default_scope: ""` the GitHub strategy's GET /user/emails fails and
      # the user payload arrives with NO "emails" key at all. That is the shape
      # that made this gate unsatisfiable in practice, so it is pinned here:
      # absence of the claim must refuse, and the fix for it is the scope in
      # `OAuthConfig`, not a loosening of this rule.
      email = unique_email()
      _user = local_user(email)

      data = oauth_data(email, %{provider: "github", raw_info: %{user: %{"login" => "someone"}}})

      assert {:error, :provider_email_unverified} = OAuth.find_or_create_user(data)
    end

    test "the operator switch lifts the requirement and putting it back restores it" do
      email = unique_email()
      user = local_user(email)

      {:ok, _} = Settings.update_setting("oauth_require_verified_email", "false")

      assert {:ok, found, :found} = OAuth.find_or_create_user(oauth_data(email))
      assert found.uuid == user.uuid

      {:ok, _} = Settings.update_setting("oauth_require_verified_email", "true")

      other_email = unique_email()
      _other = local_user(other_email)

      assert {:error, :provider_email_unverified} =
               OAuth.find_or_create_user(oauth_data(other_email))
    end

    test "the setting is registered, so an operator can actually reach it" do
      # It was read by the gate but declared nowhere — not in the defaults, not
      # in the settings schema — so the documented escape hatch existed only in
      # iex. Assert both halves of the registration.
      assert Map.has_key?(Settings.get_defaults(), "oauth_require_verified_email")

      assert :oauth_require_verified_email in SettingsForm.__schema__(:fields)
    end

    test "a malformed raw_info is treated as no assertion, not as an error" do
      email = unique_email()
      _user = local_user(email)

      for raw <- [nil, "not a map", %{user: "not a map"}, %{"user" => "not a map"}, %{}] do
        data = oauth_data(email, %{raw_info: raw})
        assert {:error, :provider_email_unverified} = OAuth.find_or_create_user(data)
      end
    end
  end

  describe "an identity that is already linked" do
    test "signs in on the provider uid, without consulting the email at all" do
      email = unique_email()
      user = local_user(email)
      uid = "uid_#{System.unique_integer([:positive])}"

      {:ok, _} =
        %OAuthProvider{}
        |> OAuthProvider.changeset(%{
          user_uuid: user.uuid,
          provider: "google",
          provider_uid: uid,
          provider_email: email
        })
        |> Repo.insert()

      # No verification claim, and even a different address on the callback:
      # the link itself is the proof, so this must resolve to the linked user.
      data = oauth_data("different-#{email}", %{provider: "google", provider_uid: uid})

      assert {:ok, found, :found} = OAuth.find_or_create_user(data)
      assert found.uuid == user.uuid
    end
  end

  describe "a brand-new account" do
    test "is created, but is only auto-confirmed on a provider assertion" do
      unverified_email = unique_email()

      assert {:ok, created, :created} = OAuth.find_or_create_user(oauth_data(unverified_email))
      assert created.email == unverified_email
      refute created.confirmed_at, "an unvouched address must not arrive pre-confirmed"

      verified_email = unique_email()

      data = oauth_data(verified_email, %{raw_info: %{"user" => %{"email_verified" => true}}})

      assert {:ok, confirmed, :created} = OAuth.find_or_create_user(data)
      assert confirmed.confirmed_at
    end

    test "that is left unconfirmed is sent the confirmation mail" do
      # Nothing else on this path sends it: `Auth.register_user/2` does not, and
      # only the registration controller ever did. Without this the account is
      # signed in and then bounced off every gate honouring
      # `require_email_confirmation` with an empty inbox. The token row is the
      # deterministic half of "the mail went out".
      assert {:ok, created, :created} = OAuth.find_or_create_user(oauth_data(unique_email()))

      assert confirm_tokens_for(created) == 1
    end

    test "one that IS vouched for is confirmed outright and gets no such mail" do
      data = oauth_data(unique_email(), %{raw_info: %{user: %{"email_verified" => true}}})

      assert {:ok, created, :created} = OAuth.find_or_create_user(data)
      assert created.confirmed_at
      assert confirm_tokens_for(created) == 0
    end
  end

  defp confirm_tokens_for(user) do
    import Ecto.Query

    Repo.one(
      from t in UserToken,
        where: t.user_uuid == ^user.uuid and t.context == "confirm",
        select: count(t.uuid)
    )
  end
end
