defmodule PhoenixKitWeb.Live.Settings.ApiFlowSettingsTest do
  @moduledoc """
  Settings -> API, the additions of the dangerous-operation flow: the "Needs approval"
  box on the create-key form (and the badge in the keys table), the approvals card with
  its count, and the settings card for confirmation, approvals and repeats.

  The card edits the six settings of `PhoenixKit.API.FlowConfig`, all or nothing, only
  what changed, each with this admin as the actor.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Activity
  alias PhoenixKit.API.Confirm
  alias PhoenixKit.API.FlowConfig
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Keys.Key
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Test.ApiFlowHarness
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RolePermission
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @path Routes.path("/admin/settings/api")

  setup %{conn: conn} do
    # The key cache, the flowkit tools and the store; the fake module adds the media scopes.
    ApiFlowHarness.setup_flow()
    KeyTestSupport.register_fake_module!()

    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")

    for key <- ["api", "media", "media.manage"],
        do: {:ok, _} = Permissions.grant_permission(role.uuid, key)

    %{conn: log_in_user(conn, admin), admin: admin}
  end

  defp flow_params(overrides), do: Map.merge(FlowConfig.current(), overrides)

  defp save_flow(view, overrides) do
    view |> form("#api-flow-form", %{"flow" => flow_params(overrides)}) |> render_submit()
  end

  defp changed_settings(admin) do
    Activity.list(action: "setting.changed", actor_uuid: admin.uuid).entries
    |> Enum.map(& &1.metadata["key"])
    |> Enum.sort()
  end

  # A plain delete sends no PubSub message, so the page does not hear of it: the window
  # the server-side re-check is for.
  defp drop_api_silently! do
    role = Roles.get_role_by_name("Admin")

    {1, _} =
      Repo.delete_all(
        from(rp in RolePermission, where: rp.role_uuid == ^role.uuid and rp.module_key == "api")
      )

    :ok
  end

  describe "the create-key form" do
    test "has a Needs approval box, unchecked", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)
      view |> element("#api-new-key") |> render_click()

      assert has_element?(view, "#api-key-requires-approval")
      refute has_element?(view, "#api-key-requires-approval[checked]")
    end

    test "a key made with the box checked requires approval, one made without does not", %{
      conn: conn
    } do
      {:ok, view, _html} = live(conn, @path)

      view |> element("#api-new-key") |> render_click()

      view
      |> form("#create-api-key-form", %{
        "key" => %{"name" => "Agent", "requires_approval" => "true"}
      })
      |> render_submit()

      view |> element("#new-api-token-done") |> render_click()

      view |> element("#api-new-key") |> render_click()
      view |> form("#create-api-key-form", %{"key" => %{"name" => "Script"}}) |> render_submit()

      assert %Key{requires_approval: true} = Repo.get_by!(Key, name: "Agent")
      assert %Key{requires_approval: false} = Repo.get_by!(Key, name: "Script")
    end

    test "the keys table marks a key that needs approval", %{conn: conn, admin: admin} do
      scope = KeyTestSupport.scope_of(admin)
      {:ok, plain, _} = Keys.create_key(admin, scope, %{"name" => "Plain"})

      {:ok, gated, _} =
        Keys.create_key(admin, scope, %{"name" => "Gated", "requires_approval" => true})

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#api-key-#{gated.uuid}", "Needs approval")
      refute has_element?(view, "#api-key-#{plain.uuid}", "Needs approval")
    end
  end

  describe "the approvals card" do
    test "links to the queue and shows no count when nothing waits", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#api-approvals-card")

      assert has_element?(
               view,
               ~s(#api-approvals-link[href="#{Routes.path("/admin/approvals")}"])
             )

      refute has_element?(view, "#api-approvals-count")
    end

    test "shows how many approvals the person may decide", %{conn: conn, admin: admin} do
      for permission <- ["settings", "dashboard"],
          do: Permissions.grant_permission(Roles.get_role_by_name("Admin").uuid, permission)

      scope = KeyTestSupport.scope_of(admin)

      {:ok, key, _token} =
        Keys.create_key(admin, scope, %{
          "name" => "Agent",
          "scopes" => ApiFlowHarness.scopes(),
          "requires_approval" => true
        })

      {:ok, actor} = Confirm.live_actor(key.uuid)

      {:ok, _row, :created} =
        ApiFlowHarness.queue(%{actor: actor}, "flowkit.delete_items", %{"ids" => ["a"]})

      {:ok, _row, :created} =
        ApiFlowHarness.queue(%{actor: actor}, "flowkit.delete_items", %{"ids" => ["b"]})

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#api-approvals-count", "2")
    end
  end

  describe "the settings card" do
    test "shows the current values", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#api-flow-card")
      assert has_element?(view, ~s(#api-flow-confirm-batch-over[value="50"]))
      assert has_element?(view, ~s(#api-flow-confirm-ttl-seconds[value="120"]))
      assert has_element?(view, ~s(#api-flow-approval-ttl-hours[value="72"]))
      assert has_element?(view, ~s(#api-flow-approval-pending-max[value="20"]))
      assert has_element?(view, ~s(#api-flow-idempotency-ttl-hours[value="24"]))
      assert has_element?(view, ~s(#api-flow-idempotency-lease-seconds[value="120"]))
    end

    test "saving writes the settings and the history has them", %{conn: conn, admin: admin} do
      {:ok, view, _html} = live(conn, @path)

      save_flow(view, %{"confirm_batch_over" => "25", "approval_pending_max" => "5"})

      assert FlowConfig.confirm_batch_over() == 25
      assert FlowConfig.approval_pending_max() == 5
      refute has_element?(view, "#api-flow-errors")
      assert changed_settings(admin) == ["api_approval_pending_max", "api_confirm_batch_over"]
    end

    test "only the values that changed are written", %{conn: conn, admin: admin} do
      {:ok, view, _html} = live(conn, @path)

      save_flow(view, %{"approval_ttl_hours" => "48"})

      assert changed_settings(admin) == ["api_approval_ttl_hours"]
    end

    for {field, bad} <- [
          {"confirm_ttl_seconds", "9"},
          {"confirm_ttl_seconds", "601"},
          {"confirm_batch_over", "0"},
          {"confirm_batch_over", "501"},
          {"approval_pending_max", "abc"},
          {"approval_ttl_hours", "1.5"},
          {"idempotency_lease_seconds", ""},
          {"idempotency_ttl_hours", "-3"}
        ] do
      test "#{field} = #{inspect(bad)} is refused and nothing is saved", %{
        conn: conn,
        admin: admin
      } do
        before = FlowConfig.current()
        {:ok, view, _html} = live(conn, @path)

        # A valid change to another field rides along: the refusal must take it back too.
        rider =
          unquote(
            if field == "approval_pending_max",
              do: "approval_ttl_hours",
              else: "approval_pending_max"
          )

        html = save_flow(view, %{unquote(field) => unquote(bad), rider => "7"})

        assert html =~ "whole number"
        assert has_element?(view, "#api-flow-errors")
        assert FlowConfig.current() == before
        assert changed_settings(admin) == []
      end
    end

    test "a person who lost api since the page opened cannot save", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)
      before = FlowConfig.current()
      drop_api_silently!()

      html = save_flow(view, %{"confirm_batch_over" => "10"})

      assert html =~ "not allowed"
      assert FlowConfig.current() == before
    end
  end
end
