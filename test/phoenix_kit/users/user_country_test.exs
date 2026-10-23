defmodule PhoenixKit.Users.UserCountryTest do
  # DataCase: the changesets run unsafe_validate_unique, which needs a sandbox checkout.
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Users.Auth.User

  @registration %{"email" => "a@example.com", "password" => "ValidPassword123!"}

  describe "profile_changeset/3" do
    test "stores a valid code upper-cased" do
      changeset =
        User.profile_changeset(%User{email: "person@example.com"}, %{"country" => " de "},
          validate_email: false
        )

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :country) == "DE"
    end

    test "rejects a code no country has" do
      changeset =
        User.profile_changeset(%User{email: "person@example.com"}, %{"country" => "ZZ"},
          validate_email: false
        )

      refute changeset.valid?
      assert %{country: ["must be a valid country code"]} = errors_on(changeset)
    end

    test "rejects a name in place of a code" do
      changeset =
        User.profile_changeset(%User{email: "person@example.com"}, %{"country" => "Germany"},
          validate_email: false
        )

      refute changeset.valid?
    end

    test "a blank value clears a stored country" do
      changeset =
        User.profile_changeset(
          %User{email: "person@example.com", country: "DE"},
          %{"country" => ""},
          validate_email: false
        )

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :country) == nil
    end

    test "leaves the country alone when the form does not send one" do
      changeset =
        User.profile_changeset(
          %User{email: "person@example.com", country: "DE"},
          %{"first_name" => "Ada"},
          validate_email: false
        )

      assert Ecto.Changeset.get_field(changeset, :country) == "DE"
    end
  end

  describe "registration_changeset/3" do
    test "starts the country from the registration country" do
      attrs = Map.put(@registration, "registration_country", "ee")

      changeset =
        User.registration_changeset(%User{}, attrs, hash_password: false, validate_email: false)

      assert Ecto.Changeset.get_field(changeset, :country) == "EE"
    end

    test "does not start from a registration country no country has" do
      attrs = Map.put(@registration, "registration_country", "ZZ")

      changeset =
        User.registration_changeset(%User{}, attrs, hash_password: false, validate_email: false)

      assert Ecto.Changeset.get_field(changeset, :country) == nil
    end

    test "a country that was given is not overwritten" do
      attrs = Map.merge(@registration, %{"registration_country" => "EE", "country" => "fi"})

      changeset =
        User.registration_changeset(%User{}, attrs, hash_password: false, validate_email: false)

      assert Ecto.Changeset.get_field(changeset, :country) == "FI"
    end
  end
end
