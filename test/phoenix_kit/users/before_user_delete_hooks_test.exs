defmodule PhoenixKit.Users.BeforeUserDeleteHooksTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Users.Auth

  defmodule GoodHook do
    def before_user_delete(uuid), do: send(self(), {:hooked, __MODULE__, uuid})
  end

  defmodule RaisingHook do
    def before_user_delete(_uuid), do: raise("boom")
  end

  defmodule NoHook do
  end

  import ExUnit.CaptureLog

  test "dispatches to modules exporting the hook; a raiser never aborts" do
    uuid = Ecto.UUID.generate()

    log =
      capture_log(fn ->
        assert :ok =
                 Auth.run_before_user_delete_hooks(uuid, [GoodHook, RaisingHook, NoHook])
      end)

    assert_received {:hooked, GoodHook, ^uuid}
    assert log =~ "RaisingHook failed: boom"
  end
end
