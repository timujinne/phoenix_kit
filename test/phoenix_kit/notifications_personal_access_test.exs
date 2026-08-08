defmodule PhoenixKit.NotificationsPersonalAccessTest do
  @moduledoc """
  Notifications are delivered to every user, but reading your own used to
  require the `notifications` permission — so an account could receive mail it
  was structurally unable to open, while the notification bell's "View all"
  pointed at a tab the sidebar was hiding from that same user.

  The split: personal pages (own inbox, own preferences) need authentication
  and nothing more; the `notifications` key is reserved for administering
  *other people's*. These pin both halves, plus the trap that made this more
  than a one-line change — dropping the views from the permission map would
  have made them **unmapped**, and unmapped means Owner-only.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Notifications
  alias PhoenixKitWeb.Users.Auth, as: WebAuth

  describe "the personal pages" do
    test "are not mapped to the notifications permission" do
      # If either of these resolves to a key again, holding it becomes a
      # requirement for reading your own inbox — the bug this fixes.
      assert WebAuth.permission_key_for_admin_view(PhoenixKitWeb.Live.Notifications.Inbox) == nil

      assert WebAuth.permission_key_for_admin_view(PhoenixKitWeb.Live.Notifications.Settings) ==
               nil
    end

    test "their sidebar tabs require no permission either" do
      # Sidebar and page must agree. A tab that still names the permission
      # would hide a page the user can reach — the dead-link half of the bug,
      # just inverted.
      for tab <- Notifications.admin_tabs() do
        assert tab.permission == nil,
               "#{tab.id} still requires #{inspect(tab.permission)}"
      end
    end

    test "are marked personal, so the missing-permission lint stays honest" do
      # `ModuleRegistry` warns about permission-less admin tabs because
      # forgetting one is the common mistake. Without this flag these three
      # would warn on every boot, training people to ignore a warning that is
      # usually right.
      for tab <- Notifications.admin_tabs() do
        assert tab.personal, "#{tab.id} is permission-free but not marked personal"
      end
    end

    test "their tabs still disappear when the kill switch is off" do
      # `permission:` used to carry module-enabled filtering for free; the
      # registry only consults enabled-state for tabs that name a key. These
      # tabs carry it in `visible:` instead, and `Tab.visible?/2` only dispatches
      # on ARITY-1 functions — an arity-0 capture silently reads as "always
      # visible", which would leave the kill switch doing nothing here.
      for tab <- Notifications.admin_tabs() do
        assert is_function(tab.visible, 1),
               "#{tab.id}'s visibility must be a 1-arity function or the kill switch is ignored"
      end
    end
  end

  describe "the notifications permission" do
    test "is still a registered key with a job to do" do
      # The split does not delete the permission — it reserves it for an
      # all-users/moderation view. If this key vanished, the rebuild would have
      # nothing to gate on and existing grants would dangle.
      assert %{key: "notifications"} = Notifications.permission_metadata()
    end
  end
end
