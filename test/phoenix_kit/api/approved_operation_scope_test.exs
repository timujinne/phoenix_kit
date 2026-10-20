defmodule PhoenixKit.API.ApprovedOperationScopeTest do
  @moduledoc """
  The handler of an approved operation gets `ctx.scope` as a direct call by the key does:
  the key owner's full scope, rebuilt when the operation runs (`Confirm.live_actor/1`
  builds the actor with `Keys.actor/3`).
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiFlowHarness

  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Users.Auth.Scope

  @delete "flowkit.delete_items"

  setup do
    setup_flow()
    :ok
  end

  test "an approved operation's handler gets the key owner's scope" do
    agent = agent()
    {:ok, row, :created} = queue(agent, @delete, %{"ids" => ["a"]})
    approver = KeyTestSupport.scope_of(KeyTestSupport.owner_user())

    assert {:ok, %{status: "executed"}} = Approvals.approve(row.uuid, approver)

    assert_received {:flow, @delete, _input, %{dry_run?: false} = ctx}
    assert %Scope{} = ctx.scope
    assert ctx.scope.user.uuid == agent.owner.uuid
    assert Scope.can?(ctx.scope, "settings")
    assert ctx.actor.kind == :key
  end
end
