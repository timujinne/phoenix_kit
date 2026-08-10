defmodule PhoenixKit.MentionsRedactionTest do
  @moduledoc """
  The extra-security mode, in its own file and NOT async.

  It flips a real site setting, and settings are ETS-cached rather than
  transactional — a value written inside a sandbox transaction survives the
  rollback in the cache and would leak into whatever async test ran next.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Mentions
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth

  @uuid "018e3c4a-9f6b-7890-abcd-ef1234567890"

  defp set_redaction(value) do
    {:ok, _} = Settings.update_setting("mentions_redact_titles", value)
    :ok
  end

  test "off by default: a record's name is rarely the secret, the access is" do
    set_redaction("false")
    refute Mentions.redact_titles?()
  end

  test "on, a forbidden mention shows the label the author stored" do
    set_redaction("true")

    try do
      assert Mentions.redact_titles?()

      # `post` is registered but declares no visibility check, so it is
      # forbidden for everyone. With redaction on, nothing is resolved for
      # it — the title can only be the author's stored label.
      assert %{state: :forbidden, title: "Name At Write Time"} =
               Mentions.context("see #[post:#{@uuid}|Name At Write Time]")
               |> Map.fetch!({"post", @uuid})
    after
      set_redaction("false")
    end
  end

  describe "withhold_titles: the public-surface floor" do
    test "a forbidden mention gives up its title AND the stored label" do
      # The setting is OFF — the ordinary internal judgement, and the one
      # this install actually runs with. A public page must still be able
      # to withhold on its own account, because the two audiences share one
      # renderer and only one of them is the open web.
      set_redaction("false")

      assert %{state: :forbidden, title: "Name At Write Time"} =
               Mentions.context("see #[post:#{@uuid}|Name At Write Time]")
               |> Map.fetch!({"post", @uuid})

      assert %{state: :private} =
               Mentions.context("see #[post:#{@uuid}|Name At Write Time]",
                 withhold_titles: true
               )
               |> Map.fetch!({"post", @uuid})
    end

    test "markdown honours the withheld state instead of printing the label" do
      set_redaction("false")

      md = Mentions.to_markdown("see #[post:#{@uuid}|Leak Me]", withhold_titles: true)

      # The catch-all clause used to swallow `:private` and emit
      # `token.label`, so passing the flag into a markdown render was a
      # silent no-op — the HEEx component withheld and the comment bodies
      # right next to it did not.
      refute md =~ "Leak Me"
      assert md =~ "private item"
    end

    test "a user mention loses its admin link when withheld" do
      set_redaction("false")

      # A REAL user: a made-up uuid resolves to `:missing`, which has no
      # `:path` either and would have passed this test for entirely the
      # wrong reason.
      {:ok, user} =
        Auth.register_user(%{
          email: "mention-link-#{System.unique_integer([:positive])}@example.com",
          password: "ValidPassword123!"
        })

      text = "ping @[user:#{user.uuid}|Alice]"

      # `user` is a public type, so it is always allowed — and its resolved
      # path is an /admin/users/view URL. Linking that from a public page
      # hands an anonymous reader an admin route and a user uuid.
      open = Mentions.context(text) |> Map.fetch!({"user", user.uuid})
      assert %{state: :ok} = open
      assert is_binary(open[:path]), "baseline changed — this test no longer proves anything"

      withheld = Mentions.context(text, withhold_titles: true) |> Map.fetch!({"user", user.uuid})

      assert %{state: :ok} = withheld
      refute Map.has_key?(withheld, :path), "a public surface linked into the admin app"
    end

    test "the withheld state carries no title key at all" do
      set_redaction("false")

      state =
        Mentions.context("see #[post:#{@uuid}|Leak Me]", withhold_titles: true)
        |> Map.fetch!({"post", @uuid})

      # Not `title: nil` — absent. A renderer doing `info[:title] ||
      # token.label` would otherwise fall straight back to the label, which
      # is the record's name as of writing and exactly what withholding was
      # for.
      refute Map.has_key?(state, :title)
      refute state |> inspect() |> String.contains?("Leak Me")
    end
  end
end
