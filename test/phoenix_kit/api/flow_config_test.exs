defmodule PhoenixKit.API.FlowConfigTest do
  @moduledoc """
  `PhoenixKit.API.FlowConfig`: the seven settings of the dangerous-operation flow, read
  with defaults and clamps, and validated and written as one form.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.API.FlowConfig
  alias PhoenixKit.API.KeyTestSupport

  setup do
    KeyTestSupport.start_cache_registry!()
  end

  defp put(key, value), do: KeyTestSupport.put_setting(key, value)

  test "the flow settings have these defaults" do
    assert FlowConfig.confirm_batch_over() == 50
    assert FlowConfig.confirm_ttl_seconds() == 120
    assert FlowConfig.user_confirm_ttl_seconds() == 600
    assert FlowConfig.approval_ttl_hours() == 72
    assert FlowConfig.idempotency_ttl_hours() == 24
    assert FlowConfig.idempotency_lease_seconds() == 120
    assert FlowConfig.approval_pending_max() == 20
  end

  test "stored values are read" do
    put("api_confirm_batch_over", "10")
    put("api_confirm_ttl_seconds", "300")
    put("api_user_confirm_ttl_seconds", "3600")
    put("api_approval_ttl_hours", "6")
    put("api_idempotency_ttl_hours", "48")
    put("api_idempotency_lease_seconds", "30")
    put("api_approval_pending_max", "3")

    assert FlowConfig.confirm_batch_over() == 10
    assert FlowConfig.confirm_ttl_seconds() == 300
    assert FlowConfig.user_confirm_ttl_seconds() == 3600
    assert FlowConfig.approval_ttl_hours() == 6
    assert FlowConfig.idempotency_ttl_hours() == 48
    assert FlowConfig.idempotency_lease_seconds() == 30
    assert FlowConfig.approval_pending_max() == 3
  end

  test "the confirmation code lifetime is capped at 600 seconds" do
    put("api_confirm_ttl_seconds", "100000")
    assert FlowConfig.confirm_ttl_seconds() == 600
  end

  test "a session's confirmation lifetime is capped at a day" do
    put("api_user_confirm_ttl_seconds", "100000")
    assert FlowConfig.user_confirm_ttl_seconds() == 86_400
  end

  test "garbage, zero and negative values read as the default" do
    for bad <- ["abc", "", "0", "-5", "1.5x"] do
      put("api_confirm_batch_over", bad)
      assert FlowConfig.confirm_batch_over() == 50, inspect(bad)
    end
  end

  test "a value below the minimum reads as the default, for the settings whose minimum is above 1" do
    # `Config.int/2` already turns zero and negative numbers into the default, so only a
    # setting with a minimum above 1 can show a value that is positive and still too small.
    for {setting, reader, too_small, default} <- [
          {"api_confirm_ttl_seconds", :confirm_ttl_seconds, "9", 120},
          {"api_user_confirm_ttl_seconds", :user_confirm_ttl_seconds, "59", 600},
          {"api_idempotency_lease_seconds", :idempotency_lease_seconds, "4", 120}
        ] do
      put(setting, too_small)
      assert apply(FlowConfig, reader, []) == default, setting
    end

    put("api_confirm_ttl_seconds", "10")
    assert FlowConfig.confirm_ttl_seconds() == 10
  end

  test "an unreadable Settings store reads as the defaults" do
    put("api_approval_pending_max", "7")
    assert FlowConfig.approval_pending_max() == 7

    previous = Application.get_env(:phoenix_kit, :update_mode, false)
    Application.put_env(:phoenix_kit, :update_mode, true)
    on_exit(fn -> Application.put_env(:phoenix_kit, :update_mode, previous) end)

    assert FlowConfig.approval_pending_max() == 20
  end

  describe "the form" do
    test "fields/0 lists the seven settings in form order" do
      assert Enum.map(FlowConfig.fields(), & &1.setting) == [
               "api_confirm_batch_over",
               "api_confirm_ttl_seconds",
               "api_user_confirm_ttl_seconds",
               "api_approval_ttl_hours",
               "api_approval_pending_max",
               "api_idempotency_ttl_hours",
               "api_idempotency_lease_seconds"
             ]
    end

    test "current/0 is the text the fields show" do
      put("api_confirm_batch_over", "12")

      assert %{"confirm_batch_over" => "12", "confirm_ttl_seconds" => "120"} =
               FlowConfig.current()
    end

    test "validate/1 accepts whole numbers inside the ranges" do
      params =
        FlowConfig.current()
        |> Map.put("confirm_ttl_seconds", "600")
        |> Map.put("approval_pending_max", "1")

      assert {:ok, pairs} = FlowConfig.validate(params)
      assert {"api_confirm_ttl_seconds", 600} in pairs
      assert {"api_approval_pending_max", 1} in pairs
      assert length(pairs) == 7
    end

    test "validate/1 names every field that is out of range or not a number" do
      params =
        FlowConfig.current()
        |> Map.put("confirm_ttl_seconds", "601")
        |> Map.put("confirm_batch_over", "0")
        |> Map.put("approval_ttl_hours", "ten")
        |> Map.put("approval_pending_max", "")
        |> Map.put("user_confirm_ttl_seconds", "86401")

      assert {:error, fields} = FlowConfig.validate(params)

      assert Enum.sort(fields) ==
               Enum.sort([
                 "confirm_batch_over",
                 "confirm_ttl_seconds",
                 "user_confirm_ttl_seconds",
                 "approval_ttl_hours",
                 "approval_pending_max"
               ])
    end

    test "validate/1 treats a missing field as an error, not as the default" do
      assert {:error, ["confirm_batch_over"]} =
               FlowConfig.validate(Map.delete(FlowConfig.current(), "confirm_batch_over"))
    end

    test "save/2 writes only what changed and nothing when anything is invalid" do
      assert {:error, ["confirm_ttl_seconds"]} =
               FlowConfig.save(Map.put(FlowConfig.current(), "confirm_ttl_seconds", "9999"), [])

      assert FlowConfig.confirm_ttl_seconds() == 120

      params =
        FlowConfig.current()
        |> Map.put("confirm_batch_over", "25")
        |> Map.put("approval_pending_max", "5")

      assert {:ok, changed} = FlowConfig.save(params, [])
      assert Enum.sort(changed) == ["api_approval_pending_max", "api_confirm_batch_over"]
      assert FlowConfig.confirm_batch_over() == 25
      assert FlowConfig.approval_pending_max() == 5

      assert {:ok, []} = FlowConfig.save(FlowConfig.current(), [])
    end
  end
end
