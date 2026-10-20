defmodule PhoenixKit.Integration.AdminApprovalsTabTest do
  @moduledoc """
  The "Approvals" entry of the admin menu, end to end through a running
  `PhoenixKit.Dashboard.Registry` and the real sidebar: who is offered it, and the
  number it carries (the pending approvals that person may decide, read for that person
  on every render).

  The registry is not part of the test supervision tree, so the suite starts its own.
  """
  use PhoenixKit.DataCase, async: false

  import Phoenix.LiveViewTest, only: [render_component: 2]

  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Dashboard.{AdminTabs, Registry}
  alias PhoenixKit.Test.ApiFlowHarness
  alias PhoenixKit.Users.Auth.{Scope, User}
  alias PhoenixKit.Users.Permissions
  alias PhoenixKitWeb.Components.Dashboard.AdminSidebar

  @moduletag :capture_log
  @delete "flowkit.delete_items"
  @link ~s(a[data-tab-id="admin_approvals"])

  setup do
    ApiFlowHarness.setup_flow()
    refute Process.whereis(Registry), "a registry is already running — this suite starts its own"
    start_supervised!(Registry)
    :sys.get_state(Registry)

    %{agent: ApiFlowHarness.agent(), owner: KeyTestSupport.owner_user()}
  end

  defp scope(roles, permissions) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000bb", email: "nav@example.com"},
      authenticated?: true,
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  defp pending!(agent, ids \\ ["a"]) do
    {:ok, row, :created} = ApiFlowHarness.queue(agent, @delete, %{"ids" => ids})
    row
  end

  defp sidebar(scope) do
    html =
      render_component(&AdminSidebar.admin_sidebar/1,
        current_path: "/admin",
        scope: scope,
        locale: "en"
      )

    LazyHTML.from_fragment(html)
  end

  defp link_text(document) do
    document
    |> LazyHTML.query(@link)
    |> LazyHTML.text()
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end

  describe "the tab" do
    test "sits right after Activity, gated by api, linking to the canonical path" do
      tab = Enum.find(AdminTabs.core_tabs(), &(&1.id == :admin_approvals))
      activity = Enum.find(AdminTabs.core_tabs(), &(&1.id == :admin_activity))

      assert tab.path == "/admin/approvals"
      assert tab.permission == "api"
      assert tab.level == :admin
      assert tab.group == activity.group
      assert tab.priority > activity.priority
      assert tab.parent == nil
    end

    test "an Owner is offered it, an Admin without api is not" do
      owner = scope(["Owner"], Permissions.all_module_keys())
      admin = scope(["Admin"], ["dashboard", "users", "settings"])

      assert :admin_approvals in Enum.map(Registry.get_admin_tabs(scope: owner), & &1.id)
      refute :admin_approvals in Enum.map(Registry.get_admin_tabs(scope: admin), & &1.id)
    end

    test "an Admin who was granted api is offered it" do
      admin = scope(["Admin"], ["dashboard", "api"])
      assert :admin_approvals in Enum.map(Registry.get_admin_tabs(scope: admin), & &1.id)
    end
  end

  describe "the menu entry" do
    test "an Owner sees the link, with no number while nothing waits", %{owner: owner} do
      document = sidebar(KeyTestSupport.scope_of(owner))

      assert link_text(document) =~ "Approvals"
      assert LazyHTML.query(document, @link <> " .badge") |> Enum.count() == 0
    end

    test "an Owner sees how many approvals wait", %{agent: agent, owner: owner} do
      pending!(agent, ["a"])
      pending!(agent, ["b"])

      document = sidebar(KeyTestSupport.scope_of(owner))

      assert link_text(document) =~ "Approvals"
      assert document |> LazyHTML.query(@link <> " .badge") |> LazyHTML.text() =~ "2"
    end

    test "the creator of a key is counted for their own approvals only", %{agent: agent} do
      mine = ApiFlowHarness.agent()
      pending!(agent, ["a"])
      pending!(mine, ["b"])
      pending!(mine, ["c"])

      document = sidebar(KeyTestSupport.scope_of(mine.owner))

      assert document |> LazyHTML.query(@link <> " .badge") |> LazyHTML.text() =~ "2"
    end

    test "a person without api is offered no link and no number", %{agent: agent} do
      pending!(agent)
      admin = scope(["Admin"], ["dashboard", "users", "settings"])

      document = sidebar(admin)

      assert LazyHTML.query(document, @link) |> Enum.count() == 0
    end
  end
end
