defmodule PhoenixKit.Notifications.RenderTest do
  # DataCase (not plain ExUnit) because Render builds links via Routes.path,
  # which reads language/prefix settings from the DB.
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.Notifications.Notification
  alias PhoenixKit.Notifications.Render
  alias PhoenixKit.Notifications.Types
  alias PhoenixKit.Utils.Routes

  defp notif(action, metadata \\ %{}) do
    %Notification{
      activity: %Entry{action: action, metadata: metadata, actor_uuid: "actor-uuid"}
    }
  end

  describe "render/2 link — core account actions" do
    @account_actions ~w(
      user.roles_updated user.status_changed user.password_changed user.password_reset
      user.email_changed user.email_confirmed user.email_unconfirmed user.avatar_changed
      user.profile_updated user.note_created user.note_deleted
    )

    test "each account action links to the prefix/locale-correct settings path" do
      for action <- @account_actions do
        assert Render.render(notif(action), "en").link ==
                 Routes.path("/dashboard/settings", locale: "en"),
               "expected #{action} to link to the settings page"
      end
    end

    test "the locale is threaded into the built link" do
      en = Render.render(notif("user.note_created"), "en").link
      ru = Render.render(notif("user.note_created"), "ru").link

      assert en == Routes.path("/dashboard/settings", locale: "en")
      assert ru == Routes.path("/dashboard/settings", locale: "ru")
    end

    test "render/1 (no locale) falls back to Routes.path's default-locale resolution" do
      assert Render.render(notif("user.note_created")).link ==
               Routes.path("/dashboard/settings")
    end

    test "user.email_unconfirmed renders a dedicated icon/text, not the generic fallback" do
      view = Render.render(notif("user.email_unconfirmed"), "en")

      assert view.icon == "hero-exclamation-circle"
      assert view.text == "Your email is no longer confirmed."
    end
  end

  describe "render/2 — session actions reach the recipient's inbox" do
    # Both are logged with `target_uuid` set to the account that was ADDED, so
    # `maybe_create_from_activity/1` delivers them to that person. Without a
    # clause they rendered as the humanized action ("Session impersonated"),
    # which reads as a log line rather than a notice addressed to them.
    test "session.impersonated says who did what, not the raw action name" do
      view = Render.render(notif("session.impersonated"), "en")

      assert view.icon == "hero-identification"
      assert view.text == "An administrator signed in to your account for support."
    end

    test "session.account_added has its own copy too" do
      view = Render.render(notif("session.account_added"), "en")

      assert view.icon == "hero-user-plus"
      assert view.text == "Your account was added to another sign-in session."
    end

    test "both are claimed by a preference type, so they can be muted" do
      # An action no type claims is fail-open and therefore unmuteable — it
      # never appears in the preferences UI for the user to switch off.
      assert Types.type_for_action("session.impersonated") == "security"
      assert Types.type_for_action("session.account_added") == "security"
    end
  end

  describe "render/2 link — module-owned / unknown actions return nil" do
    test "social and account-gone and unknown actions have no core link" do
      for action <-
            ~w(user.followed post.liked post.commented comment.liked user.deleted totally.unknown) do
        assert Render.render(notif(action), "en").link == nil,
               "expected #{action} to have no core-built link (emitter must set notification_link)"
      end
    end

    test "user.followed no longer mis-routes to settings" do
      refute Render.render(notif("user.followed"), "en").link ==
               Routes.path("/dashboard/settings", locale: "en")
    end
  end

  describe "render/2 link — notification_link metadata override" do
    test "wins verbatim over a core account link" do
      link =
        Render.render(notif("user.note_created", %{"notification_link" => "/p/x"}), "en").link

      assert link == "/p/x"
    end

    test "supplies the link for module-owned actions that have none" do
      link = Render.render(notif("post.liked", %{"notification_link" => "/posts/1"}), "en").link
      assert link == "/posts/1"
    end

    test "blank override is ignored (falls through to the action link)" do
      link = Render.render(notif("user.note_created", %{"notification_link" => ""}), "en").link
      assert link == Routes.path("/dashboard/settings", locale: "en")
    end
  end

  describe "render/2 link — standalone notification (no activity)" do
    test "uses its own metadata notification_link, else nil" do
      # activity: nil mirrors a preloaded standalone notification (no activity_uuid).
      assert Render.render(%Notification{activity: nil, metadata: %{"notification_link" => "/s"}}).link ==
               "/s"

      assert Render.render(%Notification{activity: nil, metadata: %{}}).link == nil
    end
  end
end
