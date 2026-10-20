defmodule PhoenixKit.API.ProblemModulesTest do
  @moduledoc """
  The error codes a module declares (`api_problems/0`) in `PhoenixKit.API.Problem`
  and `PhoenixKit.API.MCP.Shape`, and the four codes of the old shop API that
  `PhoenixKit.API.Legacy` keeps answering until a module declares them.
  """
  # async: false - `register/1` changes global state.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Test

  alias PhoenixKit.API.Legacy
  alias PhoenixKit.API.MCP.Shape
  alias PhoenixKit.API.OpenAPI
  alias PhoenixKit.API.Problem
  alias PhoenixKit.ModuleRegistry

  defmodule DeclaringModule do
    def enabled?, do: true

    def api_problems do
      %{
        pm_over_quota: %{
          status: 402,
          title: "Over quota",
          advice: "Buy more room, then repeat."
        },
        pm_no_advice: %{status: 404, title: "Nothing here", advice: nil}
      }
    end
  end

  defmodule ShadowingModule do
    def enabled?, do: true

    def api_problems do
      %{forbidden: %{status: 418, title: "Teapot", advice: "Use a teapot."}}
    end
  end

  # What the ecommerce module declares for the four legacy codes: its own values win.
  defmodule OldCodesModule do
    def enabled?, do: true

    def api_problems do
      %{
        cart_not_found: %{status: 410, title: "Basket gone", advice: "Open a new basket."},
        insufficient_stock: %{status: 409, title: "Out of stock", advice: nil}
      }
    end
  end

  @legacy_codes %{
    cart_not_found: {404, "Cart not found", "Create a new cart and try again."},
    cart_locked: {409, "Cart locked", "The cart is already in checkout; start a new cart."},
    unsupported_source:
      {422, "Unsupported source", "This product source cannot be changed through the API."},
    insufficient_stock:
      {422, "Insufficient stock",
       "Reduce the quantities listed in context.lines; nothing was posted."}
  }

  setup do
    for {{ModuleRegistry, :warned, {:shadowed_api_problem, _, _}} = key, _} <-
          :persistent_term.get(),
        do: :persistent_term.erase(key)

    :ok
  end

  defp with_modules(modules, fun) do
    Enum.each(modules, &ModuleRegistry.register/1)

    try do
      fun.()
    after
      Enum.each(modules, &ModuleRegistry.unregister/1)
    end
  end

  defp send_problem(code) do
    conn(:get, "/")
    |> Problem.send(code, "Detail.", %{})
    |> then(&{&1.status, JSON.decode!(&1.resp_body)})
  end

  describe "a code a module declares" do
    test "answers with the module's status and title" do
      with_modules([DeclaringModule], fn ->
        assert Problem.status(:pm_over_quota) == 402

        assert {402, %{"code" => "pm_over_quota", "title" => "Over quota", "status" => 402}} =
                 send_problem(:pm_over_quota)

        assert Problem.body(:pm_over_quota, "Detail.", %{}, nil)["title"] == "Over quota"
      end)
    end

    test "is no unknown code: nothing is logged" do
      with_modules([DeclaringModule], fn ->
        assert capture_log(fn -> send_problem(:pm_over_quota) end) == ""
      end)
    end

    test "gets its advice on MCP, or the default sentence when it declares none" do
      with_modules([DeclaringModule], fn ->
        assert Shape.advice(:pm_over_quota) == "Buy more room, then repeat."
        assert Shape.advice(:pm_no_advice) == Shape.advice(:some_code_nobody_knows)
      end)
    end

    test "reaches the advice line of a failed MCP call" do
      with_modules([DeclaringModule], fn ->
        error = {:error, :pm_over_quota, "No room.", %{}, []}

        assert %{"isError" => true, "content" => [%{"text" => text} | _]} =
                 Shape.call_result(error, "2025-06-18", nil)

        assert text == "[pm_over_quota] No room. - Buy more room, then repeat."
      end)
    end

    test "is listed with core's in statuses/0 and in the OpenAPI Problem schema" do
      with_modules([DeclaringModule], fn ->
        assert Problem.statuses().pm_over_quota == 402
        assert Problem.statuses().not_found == 404

        doc = OpenAPI.build([], :public, server_url: "https://example.test", title: "Test")
        codes = doc["components"]["schemas"]["Problem"]["properties"]["code"]["enum"]

        assert "pm_over_quota" in codes

        assert codes ==
                 Problem.statuses() |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort()
      end)
    end

    test "is unknown again once its module is gone" do
      with_modules([DeclaringModule], fn -> assert Problem.status(:pm_over_quota) == 402 end)

      log = capture_log(fn -> assert {500, _} = send_problem(:pm_over_quota) end)
      assert log =~ "unknown error code"
    end

    test "cannot shadow a code of core" do
      capture_log(fn ->
        with_modules([ShadowingModule], fn ->
          assert Problem.status(:forbidden) == 403
          assert {403, %{"title" => "Forbidden"}} = send_problem(:forbidden)
          assert Shape.advice(:forbidden) =~ "required_scope"
          assert Problem.statuses().forbidden == 403
        end)
      end)
    end
  end

  describe "an unknown code" do
    test "still answers 500 with the generic title and logs it" do
      log =
        capture_log(fn ->
          assert {500, %{"code" => "pm_nobody_declared", "title" => "Error"}} =
                   send_problem(:pm_nobody_declared)
        end)

      assert log =~ "unknown error code"
    end
  end

  describe "the codes of the old shop API (Legacy)" do
    test "answer with the same status, title and MCP advice when no module declares them" do
      for {code, {status, title, advice}} <- @legacy_codes do
        assert Problem.status(code) == status, "#{code} status"
        assert Problem.body(code, "D.", %{}, nil)["title"] == title
        assert Shape.advice(code) == advice, "#{code} advice"
        assert {^status, %{"code" => code_text, "title" => ^title}} = send_problem(code)
        assert code_text == Atom.to_string(code)
        assert Problem.statuses()[code] == status
      end
    end

    test "send no unknown-code warning" do
      assert capture_log(fn -> send_problem(:cart_locked) end) == ""
    end

    test "are no longer in core's own table" do
      for code <- Map.keys(@legacy_codes), do: refute(Problem.core_code?(code))
      assert Map.keys(Legacy.problems()) |> Enum.sort() == Map.keys(@legacy_codes) |> Enum.sort()
    end

    test "give way to a module that declares them" do
      with_modules([OldCodesModule], fn ->
        assert Problem.status(:cart_not_found) == 410
        assert Problem.body(:cart_not_found, "D.", %{}, nil)["title"] == "Basket gone"
        assert Shape.advice(:cart_not_found) == "Open a new basket."

        # The declaration replaces the legacy one as a whole: no advice declared, the default.
        assert Problem.status(:insufficient_stock) == 409
        assert Shape.advice(:insufficient_stock) == Shape.advice(:some_code_nobody_knows)

        # What it does not declare stays legacy.
        assert Problem.status(:cart_locked) == 409
        assert Shape.advice(:cart_locked) =~ "checkout"
      end)
    end
  end
end
