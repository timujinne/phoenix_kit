defmodule PhoenixKit.Integration.Notifications.UpsertTest do
  @moduledoc """
  Collapsing repeat events onto one notification — "3 new comments on earlier
  chapters" rather than three rows.

  The interesting rule is when it must NOT collapse. Folding into something
  the user has already read would hide the new event behind a row they have
  dismissed from their attention, which is exactly what the unseen-first
  ordering exists to prevent.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Notifications
  alias PhoenixKit.Notifications.Events
  alias PhoenixKit.Users.Auth

  defp create_user do
    {:ok, user} =
      Auth.register_user(%{
        email: "notif_upsert_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    user
  end

  defp texts(user) do
    {rows, _} = Notifications.list_for_user(user.uuid)
    Enum.map(rows, &get_in(&1.metadata, ["notification_text"]))
  end

  describe "upsert_inapp/3" do
    test "a repeat event refreshes the standing row instead of adding one" do
      user = create_user()

      {:ok, _} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "1 new comment"})
      {:ok, _} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "2 new comments"})
      {:ok, _} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "3 new comments"})

      assert texts(user) == ["3 new comments"]
      assert Notifications.count_unread(user.uuid) == 1
    end

    test "a different key gets its own row" do
      user = create_user()

      {:ok, _} = Notifications.upsert_inapp(user.uuid, "comments:1", %{text: "chapter one"})
      {:ok, _} = Notifications.upsert_inapp(user.uuid, "comments:2", %{text: "chapter two"})

      assert length(texts(user)) == 2
    end

    test "a different user's notification is never collapsed into" do
      a = create_user()
      b = create_user()

      {:ok, _} = Notifications.upsert_inapp(a.uuid, "comments:42", %{text: "for a"})
      {:ok, _} = Notifications.upsert_inapp(b.uuid, "comments:42", %{text: "for b"})

      assert texts(a) == ["for a"]
      assert texts(b) == ["for b"]
    end

    test "once read, the next event is news again" do
      # The rule that matters. Collapsing into a row the user has already read
      # would hide the new event inside something they have finished with, and
      # the unread count would not move.
      user = create_user()

      {:ok, first} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "1 new"})
      {:ok, _} = Notifications.mark_seen(user.uuid, first.uuid)

      {:ok, second} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "1 more"})

      refute second.uuid == first.uuid
      assert Notifications.count_unread(user.uuid) == 1
      assert length(texts(user)) == 2
    end

    test "a dismissed row is not resurrected" do
      user = create_user()

      {:ok, first} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "1 new"})
      {:ok, _} = Notifications.dismiss(user.uuid, first.uuid)

      {:ok, second} = Notifications.upsert_inapp(user.uuid, "comments:42", %{text: "1 more"})

      refute second.uuid == first.uuid
    end

    test "extra metadata is merged, not replaced" do
      user = create_user()

      {:ok, _} =
        Notifications.upsert_inapp(user.uuid, "k", %{
          text: "first",
          metadata: %{"chapter" => "12", "keep" => "me"}
        })

      {:ok, updated} =
        Notifications.upsert_inapp(user.uuid, "k", %{
          text: "second",
          metadata: %{"chapter" => "13"}
        })

      assert updated.metadata["chapter"] == "13"
      assert updated.metadata["keep"] == "me", "unmentioned keys must survive the patch"
      assert updated.metadata["dedupe_key"] == "k", "the key it collapsed on must survive too"
      assert updated.metadata["notification_text"] == "second"
    end

    test "caller metadata cannot clobber the dedupe key" do
      # The reserved keys are stamped AFTER the caller's metadata merges. The
      # old order let a passed-through metadata map (say, copied off a prior
      # notification) overwrite the key the upsert had just decided on —
      # which silently turned collapsing off for that key, with no error.
      user = create_user()

      {:ok, first} =
        Notifications.upsert_inapp(user.uuid, "k", %{
          text: "1 new",
          metadata: %{"dedupe_key" => "stale", "keep" => "me"}
        })

      assert first.metadata["dedupe_key"] == "k",
             "the key the API collapsed on must win over pass-through metadata"

      {:ok, second} = Notifications.upsert_inapp(user.uuid, "k", %{text: "2 new"})
      assert second.uuid == first.uuid, "collapsing must still work after the attempt"
      assert second.metadata["keep"] == "me"
    end

    test "atom-keyed caller metadata lands in the same namespace as the display fields" do
      # `%{notification_text: ...}` and `%{"notification_text" => ...}` are one
      # key in jsonb but two in an Elixir map — which one won the JSON encoding
      # was adapter-order-dependent. Keys are normalized to strings before the
      # display fields stamp on top.
      user = create_user()

      {:ok, n} =
        Notifications.upsert_inapp(user.uuid, "k", %{
          text: "the real text",
          metadata: %{notification_text: "the impostor", chapter: "12"}
        })

      assert n.metadata["notification_text"] == "the real text"
      assert n.metadata["chapter"] == "12"
      refute Map.has_key?(n.metadata, :notification_text)
    end

    test "the unique index turns a raced double-insert into a collapse" do
      # Two concurrent upserts for the same absent key both read nil from the
      # find. The loser's insert now trips the V170 partial unique index
      # instead of standing up a duplicate unseen row, and the public API
      # retries the find and folds.
      user = create_user()

      {:ok, first} = Notifications.create_inapp(user.uuid, %{text: "1", dedupe_key: "k"})

      # What the race's loser does: insert without re-checking.
      assert {:error, %Ecto.Changeset{}} =
               Notifications.create_inapp(user.uuid, %{text: "2", dedupe_key: "k"}),
             "a second unseen row for the same key must be refused, not inserted"

      {:ok, updated} = Notifications.upsert_inapp(user.uuid, "k", %{text: "3"})
      assert updated.uuid == first.uuid
      assert texts(user) == ["3"]
    end

    test "unkeyed rows are untouched by the uniqueness rule" do
      # The index is partial: everything the fan-out path creates carries no
      # dedupe key and must keep inserting freely.
      user = create_user()

      {:ok, _} = Notifications.create_inapp(user.uuid, %{text: "a"})
      {:ok, _} = Notifications.create_inapp(user.uuid, %{text: "b"})

      assert length(texts(user)) == 2
    end

    test "broadcasts both ways, so an open bell keeps up" do
      # Without this the host had to re-broadcast by hand, because the only
      # broadcast fired on insert.
      user = create_user()
      Events.subscribe(user.uuid)

      {:ok, _} = Notifications.upsert_inapp(user.uuid, "k", %{text: "first"})
      assert_receive {:notification_created, _}

      {:ok, _} = Notifications.upsert_inapp(user.uuid, "k", %{text: "second"})
      assert_receive {:notification_updated, %{metadata: %{"notification_text" => "second"}}}
    end
  end
end
