defmodule PhoenixKit.Integrations.EventsTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Integrations.Events

  # The system topic is shared with other async tests that broadcast for
  # "google"; a unique provider key keeps these assertions on their own message.
  defp unique_provider, do: "redact-test-#{System.unique_integer([:positive])}"

  describe "subscribe/0 and broadcasts" do
    test "subscribe and receive setup_saved event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_setup_saved("google", %{"status" => "configured"})
      assert_receive {:integration_setup_saved, "google", %{"status" => "configured"}}
    end

    test "subscribe and receive connected event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_connected("google", %{"status" => "connected"})
      assert_receive {:integration_connected, "google", %{"status" => "connected"}}
    end

    test "setup_saved and connected payloads never carry a field Encryption treats as sensitive, or oauth_state" do
      :ok = Events.subscribe()
      provider = unique_provider()

      data =
        Map.new(Encryption.sensitive_fields() ++ ["oauth_state"], &{&1, "secret-" <> &1})
        |> Map.merge(%{"status" => "configured", "name" => "default"})

      :ok = Events.broadcast_setup_saved(provider, data)
      assert_receive {:integration_setup_saved, ^provider, redacted_saved}

      :ok = Events.broadcast_connected(provider, data)
      assert_receive {:integration_connected, ^provider, redacted_connected}

      for redacted <- [redacted_saved, redacted_connected] do
        assert redacted == %{"status" => "configured", "name" => "default"}
      end
    end

    test "oauth_state is still redacted from broadcasts" do
      :ok = Events.subscribe()
      provider = unique_provider()

      :ok =
        Events.broadcast_connected(provider, %{"oauth_state" => "csrf-nonce", "status" => "ok"})

      assert_receive {:integration_connected, ^provider, payload}
      assert payload == %{"status" => "ok"}
    end

    test "subscribe and receive disconnected event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_disconnected("google")
      assert_receive {:integration_disconnected, "google"}
    end

    test "subscribe and receive validated event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_validated("google", :ok)
      assert_receive {:integration_validated, "google", :ok}
    end

    test "subscribe and receive validated error event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_validated("google", {:error, "timeout"})
      assert_receive {:integration_validated, "google", {:error, "timeout"}}
    end

    test "subscribe and receive connection_added event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_connection_added("google", "personal")
      assert_receive {:integration_connection_added, "google", "personal"}
    end

    test "subscribe and receive connection_removed event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_connection_removed("google", "personal")
      assert_receive {:integration_connection_removed, "google", "personal"}
    end

    test "subscribe and receive connection_renamed event" do
      :ok = Events.subscribe()
      :ok = Events.broadcast_connection_renamed("google", "personal", "work")
      assert_receive {:integration_connection_renamed, "google", "personal", "work"}
    end
  end
end
