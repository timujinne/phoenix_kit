defmodule PhoenixKit.Users.Auth.UsernameFromEmailTest do
  # Pure — `generate_username_from_email/1` only transforms the string. The
  # uniqueness pass that follows it in `registration_changeset/3` is what needs
  # a database, and that is covered by `user_org_changeset_test.exs`.
  use ExUnit.Case, async: true

  alias PhoenixKit.Users.Auth.User

  describe "generate_username_from_email/1" do
    test "keeps a plain ASCII local part, with dots as underscores" do
      assert User.generate_username_from_email("john.smith@example.com") == "john_smith"
    end

    test "folds accents instead of deleting the letters under them" do
      # `clean_username/1` strips anything outside [a-zA-Z0-9_], so without the
      # transliteration pass this returned "lo_kask" — the first letter of the
      # name silently gone.
      assert User.generate_username_from_email("Ülo.Kask@example.com") == "ulo_kask"
      assert User.generate_username_from_email("josé@example.com") == "jose"
    end

    test "transliterates a Cyrillic local part rather than collapsing it" do
      assert User.generate_username_from_email("Иван@example.com") == "ivan"
    end

    test "still prefixes a local part that does not start with a letter" do
      assert User.generate_username_from_email("123abc@example.com") == "user_123abc"
    end

    test "pads a local part shorter than the minimum length" do
      assert User.generate_username_from_email("jo@example.com") == "jo_1"
    end

    test "returns nil for a non-binary" do
      assert User.generate_username_from_email(nil) == nil
    end
  end
end
