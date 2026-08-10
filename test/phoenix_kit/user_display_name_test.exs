defmodule PhoenixKit.UserDisplayNameTest do
  @moduledoc """
  The one canonical answer to "what do we call this person in front of
  other people". Before it existed there were half a dozen private copies,
  several ending `|| user.email` — which is how a public issue board came
  to print commenters' full addresses next to their words.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Users.Auth.User

  describe "the chain, in order" do
    test "an organization is its own name" do
      assert User.display_name(%User{
               account_type: "organization",
               organization_name: "Ratelia OU",
               first_name: "Ignore",
               last_name: "Me"
             }) == "Ratelia OU"
    end

    test "a person is their name" do
      assert User.display_name(%User{first_name: "John", last_name: "Doe"}) == "John Doe"
      assert User.display_name(%User{first_name: "John"}) == "John"
      assert User.display_name(%User{last_name: "Doe"}) == "Doe"
    end

    test "falls to username, then to the local part" do
      assert User.display_name(%User{username: "jdoe", email: "j.doe@example.com"}) == "jdoe"
      assert User.display_name(%User{email: "j.doe@example.com"}) == "j.doe"
    end

    test "never blank, never nil, even for an empty struct" do
      assert User.display_name(%User{}) == "User"
      assert User.display_name(nil) == "User"
    end
  end

  describe "the blank rungs that broke the old copies" do
    test "whitespace-only names do not win" do
      # `full_name/1` returns "" (not nil) for "   ", so an unguarded chain
      # stops dead on it and renders an empty header.
      assert User.display_name(%User{first_name: "   ", username: "jdoe"}) == "jdoe"
      assert User.display_name(%User{first_name: " ", last_name: " ", email: "a@b.com"}) == "a"
    end

    test "a whitespace-only username does not win" do
      assert User.display_name(%User{username: "   ", email: "a@b.com"}) == "a"
    end

    test "an organization with no name falls through rather than rendering blank" do
      assert User.display_name(%User{
               account_type: "organization",
               organization_name: nil,
               username: "acme"
             }) == "acme"
    end
  end

  describe "the invariant that matters" do
    test "the result is never the full address" do
      # NOT "contains no @" — names are free text, so someone can set
      # first_name to "a@b.com" and defeat that. What must hold is that we
      # never hand back the address itself.
      for user <- [
            %User{email: "someone@example.com"},
            %User{email: "someone@example.com", username: "  "},
            %User{email: "someone@example.com", first_name: "", last_name: nil},
            %User{email: "someone@example.com", account_type: "organization"}
          ] do
        refute User.display_name(user) == user.email
      end
    end

    test "when the email is the only source, only the local part survives" do
      name = User.display_name(%User{email: "john.smith@corp.example.com"})

      assert name == "john.smith"
      refute name =~ "corp.example.com"
    end

    test "a pathological address still yields something renderable" do
      assert User.display_name(%User{email: "@nolocal.com"}) == "User"
      assert User.display_name(%User{email: ""}) == "User"
    end
  end
end
