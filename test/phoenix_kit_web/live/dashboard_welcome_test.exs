defmodule PhoenixKitWeb.Live.DashboardWelcomeTest do
  @moduledoc """
  The ungated half of `/admin`.

  `/admin` is the landing page every authenticated visitor can be sent to, so
  this block has to render for a scope that holds nothing at all — no
  permissions, no name, and (defensively) no user. DB-free: every scope is a
  literal struct and the block reads nothing but the scope.
  """
  use ExUnit.Case, async: false

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKitWeb.Live.Dashboard

  setup do
    previous = Gettext.get_locale(PhoenixKitWeb.Gettext)
    on_exit(fn -> Gettext.put_locale(PhoenixKitWeb.Gettext, previous) end)
    :ok
  end

  defp welcome(scope) do
    assigns = %{scope: scope}

    ~H"""
    <Dashboard.welcome_block scope={@scope} />
    """
    |> rendered_to_string()
  end

  # What the visitor actually reads. The name is appended to the translated
  # greeting across an element boundary, so only the tag-stripped text can
  # prove there is no stray space before the comma.
  defp text(html) do
    html
    |> String.replace(~r/<[^>]*>/, "")
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end

  defp scope(user_attrs) do
    %Scope{
      user: struct!(User, Map.merge(%{uuid: "0193a5e4-0000-7000-8000-0000000000a1"}, user_attrs)),
      authenticated?: true,
      cached_roles: ["User"],
      cached_permissions: MapSet.new([])
    }
  end

  test "a permission-less user with a name is greeted by name" do
    html = welcome(scope(%{first_name: "Jane", last_name: "Doe", email: "jane@example.com"}))

    assert text(html) =~ "Welcome back, Jane Doe"
    refute text(html) =~ "Welcome back ,"
  end

  test "the email is shown alongside a name, so the visitor sees which account" do
    html = welcome(scope(%{first_name: "Jane", last_name: "Doe", email: "jane@example.com"}))

    assert text(html) == "Welcome back, Jane Doe jane@example.com"
  end

  test "with no name the greeting falls back to the email and does not repeat it" do
    html = welcome(scope(%{email: "nameless@example.com"}))

    assert text(html) == "Welcome back, nameless@example.com"
  end

  test "a blank name is treated as no name, not as an empty greeting" do
    # `User.full_name/1` returns "" for an organization row whose name was
    # cleared — a nil test alone would render "Welcome back, " and nothing else.
    html =
      welcome(scope(%{account_type: "organization", organization_name: "", email: "o@e.com"}))

    assert text(html) == "Welcome back, o@e.com"
  end

  test "a scope with no user still renders a bare greeting" do
    for empty <- [%Scope{}, nil] do
      assert text(welcome(empty)) == "Welcome back"
    end
  end

  test "the greeting is translated — it reuses the existing login msgid" do
    Gettext.put_locale(PhoenixKitWeb.Gettext, "ru")

    html = welcome(scope(%{first_name: "Иван", email: "ivan@example.com"}))

    assert text(html) == "С возвращением, Иван ivan@example.com"
  end

  test "renders no <h1>: /admin's one header is the layout breadcrumb" do
    html = welcome(scope(%{email: "jane@example.com"}))

    refute html =~ "<h1"
    assert html =~ "<h2"
  end
end
