defmodule PhoenixKitWeb.Users.QrLoginConfirmTest do
  @moduledoc """
  The phone approval screen's device panel.

  This screen exists to answer one question — *which device is asking to sign
  in as you?* — so the panel being populated is the feature, not decoration.
  Every row in it is behind a presence guard, which means "we don't know yet"
  and "there is nothing to know" both render as an empty box while the
  heading, the warning and both buttons render fully and look ready.

  The lookup used to be gated behind `connected?`, so the first render was
  always the empty one. Normally too brief to notice; behind a proxy that
  doesn't forward the WebSocket upgrade cleanly it lasts as long as the
  transport takes to fall back, and it is paid again on every remount.
  """
  # Not async: one test swaps keyfob's store, which is application-global.
  use ExUnit.Case, async: false

  alias PhoenixKit.Users.QrLogin, as: QrLoginContext
  alias PhoenixKitWeb.Users.QrLoginConfirm

  setup do
    # The keyfob store is an ETS table owned by a supervised process, which
    # nothing starts in a unit test. Started per-test so each one gets a clean
    # table, and so the two below can stop or replace it.
    start_supervised!(Keyfob.Store.ETS)
    :ok
  end

  # `mount/3` reads settings and the current scope, so the part under test —
  # what the render is handed — is reached through the same lookup rather than
  # by standing up a LiveView and a database with it.
  defp peek_state(token) do
    case QrLoginContext.peek(token) do
      {:ok, %{state: :pending, meta: meta}} -> {:pending, meta}
      {:ok, %{state: :approved, meta: meta}} -> {:approved, meta}
      _ -> {:expired, %{}}
    end
  end

  describe "the device panel's data" do
    test "is available without a connected socket" do
      meta = %{browser: "Safari", os: "iOS", ip: "203.0.113.7", requested_at: "just now"}
      {:ok, %{token: token}} = QrLoginContext.create_request(meta: meta)

      # The dead render's lookup — the one that used to be skipped, leaving
      # an approvable prompt with no device on it.
      assert {:pending, found} = peek_state(token)
      assert found.browser == "Safari"
      assert found.os == "iOS"
      assert found.ip == "203.0.113.7"
    end

    test "a request nobody minted reads as expired, not as a blank prompt" do
      assert {:expired, %{}} = peek_state("never-existed")
    end
  end

  describe "when the store cannot answer" do
    test "a store that is not running reads as expired" do
      # keyfob 0.1.1 made its own store's reads total, so this arrives as the
      # `:error` the behaviour declares rather than as a raise.
      stop_supervised!(Keyfob.Store.ETS)

      assert {:expired, %{}} = QrLoginConfirm.look_up("anything")
    end

    test "a store that RAISES still reads as expired" do
      # `Keyfob.Store` is a behaviour a host may implement over anything —
      # Redis, a database, a cluster-wide cache — and those can be unreachable
      # in ways ETS cannot. The `case` in `look_up/1` matches return values, so
      # a raise would go straight past it, and this runs on the disconnected
      # render where that is a 500 page rather than a LiveView that quietly
      # remounts.
      Application.put_env(:keyfob, :store, __MODULE__.RaisingStore)
      on_exit(fn -> Application.delete_env(:keyfob, :store) end)

      assert {:expired, %{}} = QrLoginConfirm.look_up("anything")
    end

    test "a store that EXITS still reads as expired" do
      # The other half of the pair, and the likelier half. A host store over
      # Redis or a database is reached through a `GenServer.call`, which does not
      # raise when the process is gone or wedged — it EXITS (`:noproc`,
      # `:timeout`). `rescue` does not catch that, so with only the raise clause
      # this escaped `look_up/1` entirely and became the 500 on the dead render
      # that the guard exists to prevent.
      #
      # This module's own dependency note names both shapes: before keyfob 0.1.1
      # an unreachable store made its reads raise "and its GenServer-backed
      # calls exit".
      Application.put_env(:keyfob, :store, __MODULE__.ExitingStore)
      on_exit(fn -> Application.delete_env(:keyfob, :store) end)

      assert {:expired, %{}} = QrLoginConfirm.look_up("anything")
    end
  end

  defmodule ExitingStore do
    @moduledoc false
    @behaviour Keyfob.Store

    # Exactly how a GenServer-backed store fails when it is not running: the
    # call exits with `:noproc`. Not `exit/1` by hand — the point is the shape
    # a real store produces.
    @impl true
    def get(_key), do: GenServer.call(:phoenix_kit_no_such_keyfob_store, :get)

    @impl true
    def put(_key, _value, _ttl), do: :ok
    @impl true
    def update(_key, _fun), do: :error
    @impl true
    def take(_key), do: :error
    @impl true
    def delete(_key), do: :ok
  end

  defmodule RaisingStore do
    @moduledoc false
    @behaviour Keyfob.Store

    @impl true
    def get(_key), do: raise("the store is unreachable")

    @impl true
    def put(_key, _value, _ttl), do: :ok
    @impl true
    def update(_key, _fun), do: :error
    @impl true
    def take(_key), do: :error
    @impl true
    def delete(_key), do: :ok
  end

  describe "identifying_details?/1" do
    # Decides between showing a bare empty panel and saying that nothing about
    # the device could be determined — the difference between "still loading"
    # and "nothing to load", on the screen where that IS the decision.
    test "any one identifying field is enough" do
      for key <- [:browser, :os, :ip, :location] do
        assert QrLoginConfirm.identifying_details?(%{key => "something"}),
               "#{key} should count as identifying"
      end
    end

    test "a timestamp alone is not" do
      # Stamped on every request, so its presence says nothing about whether
      # we know WHO is asking — the panel would still render as a blank box.
      refute QrLoginConfirm.identifying_details?(%{requested_at: "2026-08-10 12:00:00Z"})
    end

    test "nothing at all is not" do
      refute QrLoginConfirm.identifying_details?(%{})
    end

    test "blank and non-string values do not count" do
      refute QrLoginConfirm.identifying_details?(%{browser: ""})
      refute QrLoginConfirm.identifying_details?(%{browser: "   "})
      refute QrLoginConfirm.identifying_details?(%{browser: nil})
    end
  end
end
