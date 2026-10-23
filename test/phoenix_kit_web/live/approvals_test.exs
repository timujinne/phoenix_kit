defmodule PhoenixKitWeb.Live.ApprovalsTest do
  @moduledoc """
  Approvals (`/admin/approvals`): who sees what, what a card says, approving and
  rejecting from the page, the outcomes the page reports in words, live updates, and the
  server-side re-checks of a forged or stale event.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Canonical
  alias PhoenixKit.API.Confirm
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Notifications
  alias PhoenixKit.Test.ApiFlowHarness
  alias PhoenixKit.Test.ApiFlowStore
  alias PhoenixKit.Test.ApiFlowTools
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RolePermission
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @path Routes.path("/admin/approvals")
  @old_path Routes.path("/admin/settings/api/approvals")
  @delete "flowkit.delete_items"

  setup %{conn: conn} do
    ApiFlowHarness.setup_flow()

    # Approving runs the operation in a task of this supervisor, so a closed page cannot stop it; the app
    # starts it, the test environment does not.
    start_supervised!({Task.Supervisor, name: PhoenixKit.TaskSupervisor})
    owner = Auth.get_user_by_email("seed-owner@phoenixkit.test")
    %{conn: log_in_user(conn, owner), agent: ApiFlowHarness.agent()}
  end

  # An Admin who holds `api` and the tool permissions, with a key of their own that
  # needs approval: a person who is not the Owner and may decide only their own keys.
  defp admin_with_key do
    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")
    for key <- ["api", "settings", "dashboard"], do: Permissions.grant_permission(role.uuid, key)

    {:ok, key, _token} =
      Keys.create_key(admin, KeyTestSupport.scope_of(admin), %{
        "name" => "Admin's agent",
        "scopes" => ApiFlowHarness.scopes(),
        "requires_approval" => true
      })

    {:ok, actor} = Confirm.live_actor(key.uuid)
    %{admin: admin, key: key, agent: %{actor: actor}}
  end

  defp pending!(agent, ids \\ ["a", "b"]) do
    {:ok, row, :created} = ApiFlowHarness.queue(agent, @delete, %{"ids" => ids})
    row
  end

  defp reload(row), do: Repo.get!(Confirmation, row.uuid)

  defp requested_at!(row, %DateTime{} = at) do
    {1, _} =
      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid), set: [inserted_at: at])

    :ok
  end

  # Where the card of `row` sits in the page.
  defp card_position(html, row) do
    {position, _length} = :binary.match(html, ~s(id="approval-#{row.uuid}"))
    position
  end

  defp text_of(html), do: html |> LazyHTML.from_fragment() |> LazyHTML.text() |> String.trim()

  defp card_count(html, row),
    do: html |> String.split(~s(id="approval-#{row.uuid}")) |> length() |> Kernel.-(1)

  # An approval whose preview is exactly `preview`: what a module other than the test tools
  # would have written.
  defp pending_with_preview!(agent, preview, ids \\ ["a"]) do
    input = %{"ids" => ids}

    {:ok, row, :created} =
      Approvals.request(%{
        actor: agent.actor,
        tool: @delete,
        input: input,
        input_hash: Canonical.hash(@delete, input),
        preview: preview,
        fingerprint: "fp",
        context: %{}
      })

    row
  end

  # The page's scope is captured at mount; a plain delete sends no PubSub message, so the
  # page does not hear of it: the window the server-side re-check is for.
  defp drop_api_silently! do
    role = Roles.get_role_by_name("Admin")

    {1, _} =
      Repo.delete_all(
        from(rp in RolePermission, where: rp.role_uuid == ^role.uuid and rp.module_key == "api")
      )

    :ok
  end

  describe "the list" do
    test "an Owner sees every pending approval with its key, tool and preview", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approvals-page")
      assert has_element?(view, "#approval-title-#{row.uuid}", "Delete items")
      assert has_element?(view, "#approval-requester-#{row.uuid}", agent.key.name)
      assert has_element?(view, "#approval-preview-#{row.uuid}", "delete")
      assert has_element?(view, "#approve-#{row.uuid}")
      assert has_element?(view, "#reject-#{row.uuid}")
      refute has_element?(view, "#approvals-empty")
    end

    test "a short preview shows the totals and every row, and Approve asks once", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-totals-#{row.uuid}", "2")
      assert has_element?(view, "#approval-rows-#{row.uuid}")
      refute has_element?(view, "#approval-truncated-#{row.uuid}")
      refute has_element?(view, "#approve-#{row.uuid}[data-confirm]")
    end

    test "a long preview is cut visibly: totals first, 25 rows, a notice with the rest, a second confirmation",
         %{conn: conn, agent: agent} do
      row = pending!(agent, Enum.map(1..30, &"item-#{&1}"))
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-totals-#{row.uuid}", "30")
      assert has_element?(view, "#approval-truncated-#{row.uuid}", "5")
      assert has_element?(view, "#approve-#{row.uuid}[data-confirm]")

      assert view
             |> element("#approval-rows-#{row.uuid}")
             |> render()
             |> String.split("item-")
             |> length() == 26
    end

    test "says so when nothing waits", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)
      assert has_element?(view, "#approvals-empty")
    end

    test "an approval queued while the page is open appears", %{conn: conn, agent: agent} do
      {:ok, view, _html} = live(conn, @path)
      assert has_element?(view, "#approvals-empty")

      row = pending!(agent)
      _ = :sys.get_state(view.pid)

      assert has_element?(view, "#approval-#{row.uuid}")
      refute has_element?(view, "#approvals-empty")
    end

    test "the creator of a key sees the approvals of their keys only", %{agent: other_agent} do
      mine = admin_with_key()
      pending!(other_agent, ["a"])
      my_row = pending!(mine.agent, ["b"])

      conn = log_in_user(build_conn(), mine.admin)
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-#{my_row.uuid}")
      assert view |> render() |> String.split(~s(id="approval-preview-)) |> length() == 2
    end

    test "decided approvals are listed as recent", %{conn: conn, agent: agent} do
      row = pending!(agent)
      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())
      {:ok, _} = Approvals.reject(row.uuid, owner_scope)

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approvals-recent")
      assert has_element?(view, "#recent-#{row.uuid}", "Rejected")
      refute has_element?(view, "#approval-#{row.uuid}")
    end
  end

  describe "the order of the cards" do
    test "is oldest request first, also across a month boundary", %{conn: conn, agent: agent} do
      newer = pending!(agent, ["a"])
      older = pending!(agent, ["b"])
      requested_at!(older, ~U[2026-10-31 23:00:00Z])
      requested_at!(newer, ~U[2026-11-01 01:00:00Z])

      {:ok, view, _html} = live(conn, @path)
      html = render(view)

      assert card_position(html, older) < card_position(html, newer)
    end

    test "a card listed as settled is not listed a second time as pending", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      other = pending!(agent, ["b"])
      {:ok, view, _html} = live(conn, @path)

      # The window between the click and the decision: the page holds the card as settled
      # while the database still says pending, and an unrelated change reloads the lists.
      :sys.replace_state(view.pid, fn state ->
        card = Enum.find(state.socket.assigns.cards, &(&1.approval.uuid == row.uuid))
        settled = Map.put(state.socket.assigns.settled, row.uuid, %{card | state: :running})

        %{
          state
          | socket: %{state.socket | assigns: Map.put(state.socket.assigns, :settled, settled)}
        }
      end)

      Approvals.broadcast(other.uuid)
      _ = :sys.get_state(view.pid)

      assert card_count(render(view), row) == 1
      assert card_count(render(view), other) == 1
    end
  end

  describe "the card" do
    test "is headed by the tool's title and the row count, not its internal name", %{
      conn: conn,
      agent: agent
    } do
      row = pending_with_preview!(agent, %{"rows" => [%{"ref" => "a"}, %{"ref" => "b"}]})
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-title-#{row.uuid}", "Delete items")
      assert has_element?(view, "#approval-count-#{row.uuid}", "2")

      visible =
        view
        |> element("#approval-#{row.uuid}")
        |> render()
        |> LazyHTML.from_fragment()
        |> LazyHTML.text()

      refute visible =~ @delete
    end

    test "says which key asked, whose it is, and when it was asked and expires", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-requester-#{row.uuid}", agent.key.name)
      assert has_element?(view, "#approval-requester-#{row.uuid}", agent.owner.email)
      assert has_element?(view, "#approval-asked-#{row.uuid}")
      assert has_element?(view, "#approval-expires-#{row.uuid}", "Expires in")
    end

    test "names the key by its prefix, never by its token", %{conn: conn, agent: agent} do
      row = pending!(agent)
      {:ok, view, html} = live(conn, @path)

      assert has_element?(view, "#approval-key-#{row.uuid}", "pk_#{agent.key.prefix}_")
      refute html =~ agent.token
    end

    test "carries the anchor the bell's link points at, and the hook that lights it", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      owner = KeyTestSupport.owner_user()
      [notice | _] = Notifications.recent_for_user(owner.uuid, 5)
      [_path, fragment] = String.split(notice.metadata["notification_link"], "#")

      {:ok, view, _html} = live(conn, @path)

      assert fragment == "approval-#{row.uuid}"
      assert has_element?(view, "#" <> fragment)
      assert has_element?(view, ~s(#approvals-page[phx-hook="PkHashHighlight"]))
      assert has_element?(view, ~s(#approval-#{row.uuid}[class~="target:ring-2"]))
      assert has_element?(view, ~s(#approval-#{row.uuid}[class~="data-[highlight]:ring-2"]))
    end

    test "falls back to the tool's name when the tool is gone", %{conn: conn, agent: agent} do
      row = pending!(agent)
      ApiFlowTools.set_enabled(false)
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-title-#{row.uuid}", @delete)
    end
  end

  describe "the preview" do
    test "of the common shape is a table of item, field, was, becomes and change", %{
      conn: conn,
      agent: agent
    } do
      {:ok, row, :created} =
        ApiFlowHarness.queue(agent, "flowkit.set_values", %{
          "changes" => [%{"id" => "a", "value" => 110}, %{"id" => "b", "value" => 150}]
        })

      {:ok, view, _html} = live(conn, @path)
      table = "#approval-rows-#{row.uuid}"

      assert has_element?(view, "#approval-title-#{row.uuid}", "Change values")
      assert has_element?(view, table <> " th", "Item")
      assert has_element?(view, table <> " th", "Field")
      assert has_element?(view, table <> " th", "Was")
      assert has_element?(view, table <> " th", "Becomes")
      assert has_element?(view, table <> " tbody tr", "value")
      assert has_element?(view, table <> " tbody tr", "100")
      assert has_element?(view, table <> " tbody tr", "110")
      assert has_element?(view, table <> " tbody tr", "+10.0%")
      assert has_element?(view, table <> " tbody tr", "-25.0%")
      assert has_element?(view, "#approval-totals-#{row.uuid}", "updated 2")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end

    test "warnings are readable text and the item is plain text, not a link", %{
      conn: conn,
      agent: agent
    } do
      preview = %{
        "rows" => [
          %{
            "ref" => "SKU-1",
            "id" => "0198-aaaa",
            "name" => "Oak shelf",
            "action" => "update",
            "changes" => %{"price" => %{"from" => "10.00", "to" => "12.50"}},
            "warnings" => ["Shopify sync may overwrite this price."]
          }
        ],
        "totals" => %{"rows" => 1, "update" => 1}
      }

      row = pending_with_preview!(agent, preview)
      {:ok, view, _html} = live(conn, @path)
      table = "#approval-rows-#{row.uuid}"

      assert has_element?(view, table, "Oak shelf")
      assert has_element?(view, table, "SKU-1")
      assert has_element?(view, table, "Shopify sync may overwrite this price.")
      assert has_element?(view, table, "+25.0%")
      refute has_element?(view, table <> " a")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end

    test "the error of a row is read from the first-party shape: code, message and the field reasons",
         %{conn: conn, agent: agent} do
      error = %{
        "code" => "validation_failed",
        "message" => "The row does not pass validation.",
        "context" => %{
          "errors" => [
            %{"path" => "price", "message" => "must be a number"},
            %{"path" => "stock", "message" => "must be 0 or more"}
          ]
        }
      }

      row =
        pending_with_preview!(agent, %{
          "rows" => [%{"ref" => "SKU-9", "action" => "error", "error" => error}],
          "totals" => %{"rows" => 1, "error" => 1}
        })

      {:ok, view, _html} = live(conn, @path)
      cell = "#approval-row-#{row.uuid}-0"

      assert has_element?(view, cell <> "-error", "The row does not pass validation.")
      assert has_element?(view, cell <> "-error", "validation_failed")
      assert has_element?(view, cell <> "-reasons li", "price: must be a number")
      assert has_element?(view, cell <> "-reasons li", "stock: must be 0 or more")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end

    test "an error row has no \"error\" badge next to its code and no empty cell", %{
      conn: conn,
      agent: agent
    } do
      row =
        pending_with_preview!(agent, %{
          "rows" => [
            %{
              "ref" => "SKU-9",
              "action" => "error",
              "error" => %{"code" => "not_found", "message" => "The product no longer exists."}
            },
            %{"ref" => "SKU-10", "action" => "error"}
          ]
        })

      {:ok, view, _html} = live(conn, @path)
      first = "#approval-row-#{row.uuid}-0"

      assert has_element?(view, first <> "-error", "not_found")
      refute has_element?(view, first <> "-action")
      assert has_element?(view, "#approval-row-#{row.uuid}-1-action", "error")
      assert has_element?(view, "td[colspan='5'] " <> first)
      refute has_element?(view, "#approval-rows-#{row.uuid} td:empty")
    end

    test "an error whose context says more than field errors opens the technical details", %{
      conn: conn,
      agent: agent
    } do
      preview = %{
        "rows" => [
          %{
            "ref" => "SKU-9",
            "error" => %{
              "code" => "not_found",
              "message" => "No product matches this reference.",
              "context" => %{"ref" => "sentinel-ref-4471"}
            }
          }
        ]
      }

      row = pending_with_preview!(agent, preview)
      {:ok, view, _html} = live(conn, @path)
      details = "#approval-technical-#{row.uuid}"

      assert has_element?(view, "#approval-row-#{row.uuid}-0-error", "No product matches")
      assert has_element?(view, details <> " pre", "sentinel-ref-4471")
    end

    test "an empty action or error draws nothing", %{conn: conn, agent: agent} do
      row =
        pending_with_preview!(agent, %{"rows" => [%{"ref" => "a", "action" => "", "error" => ""}]})

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-row-#{row.uuid}-0")
      refute has_element?(view, "#approval-row-#{row.uuid}-0-action")
      refute has_element?(view, "#approval-row-#{row.uuid}-0-error")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end

    test "action and error are shown for a row that has changes too", %{
      conn: conn,
      agent: agent
    } do
      row =
        pending_with_preview!(agent, %{
          "rows" => [
            %{
              "ref" => "SKU-1",
              "action" => "update",
              "changes" => %{"price" => %{"from" => "10.00", "to" => "12.50"}},
              "error" => %{
                "code" => "stale_price",
                "message" => "refused-sentinel",
                "context" => %{}
              }
            },
            %{
              "ref" => "SKU-2",
              "action" => "delete",
              "changes" => %{
                "price" => %{"from" => "1", "to" => "2"},
                "stock" => %{"from" => "3", "to" => "4"}
              }
            }
          ]
        })

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-row-#{row.uuid}-0-action", "update")
      assert has_element?(view, "#approval-row-#{row.uuid}-0-error", "refused-sentinel")
      assert has_element?(view, "#approval-row-#{row.uuid}-1-action", "delete")
      refute has_element?(view, "#approval-row-#{row.uuid}-1-error")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end

    test "known actions and totals are put in words, unknown ones are shown as they are", %{
      conn: conn,
      agent: agent
    } do
      row =
        pending_with_preview!(agent, %{
          "rows" => [
            %{"ref" => "a", "action" => "unchanged"},
            %{"ref" => "b", "action" => "frobnicate"}
          ],
          "totals" => %{"rows" => 2, "unchanged" => 1, "frobnicate" => 1}
        })

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-row-#{row.uuid}-0-action", "unchanged")
      assert has_element?(view, "#approval-row-#{row.uuid}-1-action", "frobnicate")
      assert has_element?(view, "#approval-totals-#{row.uuid}", "frobnicate 1")
    end

    test "a row's action reads as what will happen, the counts as what was counted", %{
      conn: conn,
      agent: agent
    } do
      row =
        pending_with_preview!(agent, %{
          "rows" => [%{"ref" => "a", "action" => "update"}, %{"ref" => "b", "action" => "delete"}],
          "totals" => %{"rows" => 2, "update" => 1, "delete" => 1}
        })

      {:ok, view, _html} = live(conn, @path)
      text = fn selector -> view |> element(selector) |> render() |> text_of() end

      assert text.("#approval-row-#{row.uuid}-0-action") == "update"
      assert text.("#approval-row-#{row.uuid}-1-action") == "delete"
      assert has_element?(view, "#approval-totals-#{row.uuid}", "updated 1")
      assert has_element?(view, "#approval-totals-#{row.uuid}", "deleted 1")
    end

    test "a row action written in the past tense reads the same, an unknown one is cleaned up", %{
      conn: conn,
      agent: agent
    } do
      row =
        pending_with_preview!(agent, %{
          "rows" => [
            %{"ref" => "a", "action" => "updated"},
            %{"ref" => "b", "action" => "created"},
            %{"ref" => "c", "action" => "removed"},
            %{"ref" => "d", "action" => "skipped"},
            %{"ref" => "e", "action" => "deleted"},
            %{"ref" => "f", "action" => "create_version"}
          ]
        })

      {:ok, view, _html} = live(conn, @path)

      text = fn i ->
        view |> element("#approval-row-#{row.uuid}-#{i}-action") |> render() |> text_of()
      end

      assert Enum.map(0..5, text) == [
               "update",
               "create",
               "remove",
               "skip",
               "delete",
               "create version"
             ]
    end

    test "the technical details stay open while the page is redrawn", %{
      conn: conn,
      agent: agent
    } do
      row = pending_with_preview!(agent, %{"module_specific" => %{"clue" => "c"}})
      {:ok, view, _html} = live(conn, @path)

      # Only the markup is asserted: that the element stays open across a patch is done by
      # the browser's LiveView client and cannot be seen here.
      mounted =
        view
        |> element("#approval-technical-#{row.uuid}")
        |> render()
        |> LazyHTML.from_fragment()
        |> LazyHTML.attribute("phx-mounted")

      assert [json] = mounted
      assert json =~ "ignore_attrs"
      assert json =~ "open"
    end

    test "what does not fit the shape is kept under collapsed technical details", %{
      conn: conn,
      agent: agent
    } do
      preview = %{
        "rows" => [%{"ref" => "x", "action" => "update", "fancy" => %{"deep" => ["a", 1]}}],
        "module_specific" => %{"clue" => "sentinel-clue-8812"}
      }

      row = pending_with_preview!(agent, preview)
      {:ok, view, _html} = live(conn, @path)
      details = "#approval-technical-#{row.uuid}"

      assert has_element?(view, details <> " summary", "Technical details")
      refute has_element?(view, details <> "[open]")
      assert has_element?(view, details <> " pre", "sentinel-clue-8812")
      assert has_element?(view, details <> " pre", "fancy")
      assert has_element?(view, "#approval-rows-#{row.uuid}", "x")
    end

    test "an approval with nothing to show still renders", %{conn: conn, agent: agent} do
      row = pending_with_preview!(agent, %{})
      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, "#approval-#{row.uuid}")
      refute has_element?(view, "#approval-rows-#{row.uuid}")
      refute has_element?(view, "#approval-technical-#{row.uuid}")
    end
  end

  describe "the old address" do
    test "redirects to the new one", %{conn: conn} do
      assert {:error, {:live_redirect, %{to: to}}} = live(conn, @old_path)
      assert to == @path
    end

    test "is still gated by api", %{} do
      {admin, _token} = create_admin_user()
      result = live(log_in_user(build_conn(), admin), @old_path)

      assert match?({:error, {kind, _}} when kind in [:redirect, :live_redirect], result)
      refute match?({:error, {:live_redirect, %{to: @path}}}, result)
    end
  end

  describe "approving" do
    test "runs the operation and moves the approval to the recent list", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)

      view |> element("#approve-#{row.uuid}") |> render_click()
      html = render_async(view)

      assert html =~ "executed"
      assert reload(row).status == "executed"
      assert ApiFlowStore.items() == %{"c" => 300}

      # The card stays where it was and says what happened; there is nothing left to press.
      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Done: deleted 2")
      assert has_element?(view, "#approval-status-#{row.uuid}", "Executed")
      refute has_element?(view, "#approve-#{row.uuid}")
      refute has_element?(view, "#reject-#{row.uuid}")
      refute has_element?(view, "#approval-expires-#{row.uuid}")
      refute has_element?(view, "#recent-#{row.uuid}")
    end

    test "a running approval says so and offers no buttons until it ends", %{
      conn: conn,
      agent: agent
    } do
      ApiFlowStore.set_gate(self())

      {:ok, row, :created} =
        ApiFlowHarness.queue(agent, "flowkit.progress_write", %{"hold" => true})

      {:ok, view, _html} = live(conn, @path)
      view |> element("#approve-#{row.uuid}") |> render_click()
      assert_receive {:held, worker}, 5_000
      _ = :sys.get_state(view.pid)

      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Running.")
      refute has_element?(view, "#approve-#{row.uuid}")
      refute has_element?(view, "#reject-#{row.uuid}")
      refute has_element?(view, "#approval-status-#{row.uuid}")

      send(worker, :release)
      _ = render_async(view)

      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Done")
      refute has_element?(view, "#approval-outcome-#{row.uuid}", "Running.")
    end

    test "an approval decided earlier is in the recent list, in words", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)
      view |> element("#approve-#{row.uuid}") |> render_click()
      _ = render_async(view)

      {:ok, fresh, _html} = live(conn, @path)

      refute has_element?(fresh, "#approval-#{row.uuid}")
      assert has_element?(fresh, "#recent-#{row.uuid}", "Executed")
      assert has_element?(fresh, "#recent-outcome-#{row.uuid}", "Done: deleted 2")
    end

    test "says what happened when the values changed", %{conn: conn, agent: agent} do
      row = pending!(agent)
      ApiFlowStore.put("a", 999)
      {:ok, view, _html} = live(conn, @path)

      view |> element("#approve-#{row.uuid}") |> render_click()
      html = render_async(view)

      assert html =~ "nothing was written"

      assert has_element?(
               view,
               "#approval-outcome-#{row.uuid}",
               "Not executed: the data changed since the request; nothing was written."
             )

      assert reload(row).status == "stale"
      assert ApiFlowStore.items()["a"] == 999
    end

    test "says why the operation could not run", %{conn: conn, agent: agent} do
      {:ok, row, :created} =
        ApiFlowHarness.queue(agent, "flowkit.progress_write", %{"fail" => true})

      {:ok, view, _html} = live(conn, @path)

      view |> element("#approve-#{row.uuid}") |> render_click()
      html = render_async(view)

      assert html =~ "could not run"
      assert html =~ "Two lines are short."
      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Failed: insufficient_stock")
      assert reload(row).status == "failed"
    end

    test "an approval someone else decided meanwhile is reported, not run twice", %{
      conn: conn,
      agent: agent
    } do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)
      {:ok, _} = Approvals.reject(row.uuid, KeyTestSupport.scope_of(KeyTestSupport.owner_user()))

      html = render_hook(view, "approve", %{"uuid" => row.uuid})
      _ = render_async(view)

      assert reload(row).status == "rejected"
      assert ApiFlowStore.items() == %{"a" => 100, "b" => 200, "c" => 300}
      assert is_binary(html)
      assert render(view) =~ "no longer waiting"
    end

    test "an operation already running still finishes when the page goes away", %{
      conn: conn,
      agent: agent
    } do
      # The handler stops at `hold` and tells this test, so the page can be killed in the
      # middle of the operation (a closed tab, a dropped socket, a deploy of the page).
      ApiFlowStore.set_gate(self())

      {:ok, row, :created} =
        ApiFlowHarness.queue(agent, "flowkit.progress_write", %{"hold" => true})

      {:ok, view, _html} = live(conn, @path)
      Process.flag(:trap_exit, true)

      view |> element("#approve-#{row.uuid}") |> render_click()
      assert_receive {:held, worker}, 5_000
      assert reload(row).status == "executing"
      worker_ref = Process.monitor(worker)

      page = view.pid
      # Let the page finish reloading after the approval's change broadcasts: a process killed
      # in the middle of a sandboxed query takes the shared test connection down with it.
      _ = :sys.get_state(page)
      page_ref = Process.monitor(page)
      Process.exit(page, :kill)
      assert_receive {:DOWN, ^page_ref, :process, ^page, :killed}, 5_000

      # The page is gone and the operation is still waiting at its gate, not killed with it.
      refute_receive {:DOWN, ^worker_ref, :process, ^worker, _reason}, 300
      assert reload(row).status == "executing"

      send(worker, :release)
      assert_receive {:DOWN, ^worker_ref, :process, ^worker, _reason}, 5_000

      done = reload(row)
      assert done.status == "executed"
      assert done.result["done"] == 2
    end
  end

  describe "the menu number" do
    @badge ~s(a[data-tab-id="admin_approvals"] .badge)

    # The registry is not part of the test supervision tree; the menu is drawn only with one.
    setup do
      refute Process.whereis(PhoenixKit.Dashboard.Registry),
             "a registry is already running - this suite starts its own"

      start_supervised!(PhoenixKit.Dashboard.Registry)
      :sys.get_state(PhoenixKit.Dashboard.Registry)
      :ok
    end

    test "while nothing uses approvals the entry is gone, the page and the Settings link answer",
         %{conn: conn, agent: agent} do
      {1, _} =
        Repo.update_all(from(k in Keys.Key, where: k.uuid == ^agent.key.uuid),
          set: [requires_approval: false]
        )

      {:ok, view, _html} = live(conn, @path)
      assert has_element?(view, "#approvals-page")
      refute has_element?(view, ~s(a[data-tab-id="admin_approvals"]))

      {:ok, settings, _html} = live(conn, Routes.path("/admin/settings/api"))
      assert has_element?(settings, "#api-approvals-link")
      refute has_element?(settings, ~s(a[data-tab-id="admin_approvals"]))
    end

    test "follows the queue while the page is open", %{conn: conn, agent: agent} do
      {:ok, view, _html} = live(conn, @path)
      assert has_element?(view, ~s(a[data-tab-id="admin_approvals"]))
      refute has_element?(view, @badge)

      first = pending!(agent, ["a"])
      _ = :sys.get_state(view.pid)
      assert has_element?(view, @badge, "1")

      pending!(agent, ["b"])
      _ = :sys.get_state(view.pid)
      assert has_element?(view, @badge, "2")

      view |> element("#reject-#{first.uuid}") |> render_click()
      _ = :sys.get_state(view.pid)
      assert has_element?(view, @badge, "1")
    end

    test "stops counting at 99+", %{conn: conn, agent: agent} do
      row = pending!(agent)
      base = row |> Map.from_struct() |> Map.delete(:__meta__)

      copies =
        for n <- 1..100,
            do: %{base | uuid: UUIDv7.generate(), input_hash: String.pad_leading("#{n}", 64, "0")}

      {100, _} = Repo.insert_all(Confirmation, copies)

      {:ok, view, _html} = live(conn, @path)

      assert has_element?(view, @badge, "99+")
    end
  end

  describe "the creator of a key deciding" do
    test "approves their own approval and the card says what happened" do
      mine = admin_with_key()
      row = pending!(mine.agent, ["a"])
      {:ok, view, _html} = live(log_in_user(build_conn(), mine.admin), @path)

      view |> element("#approve-#{row.uuid}") |> render_click()
      _ = render_async(view)

      assert reload(row).status == "executed"
      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Done: deleted 1")
      assert has_element?(view, "#approval-requester-#{row.uuid}", mine.admin.email)
    end

    test "hears that they lost api and sees nothing more, settled cards included" do
      mine = admin_with_key()
      row = pending!(mine.agent, ["a"])
      other = pending!(mine.agent, ["b"])
      {:ok, view, _html} = live(log_in_user(build_conn(), mine.admin), @path)
      view |> element("#reject-#{row.uuid}") |> render_click()
      assert has_element?(view, "#approval-outcome-#{row.uuid}")

      drop_api_silently!()
      Approvals.broadcast(other.uuid)
      _ = :sys.get_state(view.pid)

      refute has_element?(view, "#approval-#{row.uuid}")
      refute has_element?(view, "#approval-#{other.uuid}")
      assert has_element?(view, "#approvals-empty")
    end
  end

  describe "rejecting" do
    test "discards the approval at once", %{conn: conn, agent: agent} do
      row = pending!(agent)
      {:ok, view, _html} = live(conn, @path)

      view |> element("#reject-#{row.uuid}") |> render_click()

      assert reload(row).status == "rejected"
      assert ApiFlowStore.items() == %{"a" => 100, "b" => 200, "c" => 300}
      refute has_element?(view, "#reject-#{row.uuid}")
      assert has_element?(view, "#approval-outcome-#{row.uuid}", "Rejected: nothing was run.")
      assert render(view) =~ "rejected"
    end
  end

  describe "server-side checks" do
    test "a forged approve of an approval the person may not decide changes nothing", %{
      agent: other_agent
    } do
      theirs = pending!(other_agent)
      mine = admin_with_key()
      {:ok, view, _html} = live(log_in_user(build_conn(), mine.admin), @path)

      html = render_hook(view, "approve", %{"uuid" => theirs.uuid})
      _ = render_async(view)

      assert html =~ "not allowed" or render(view) =~ "not allowed"
      assert reload(theirs).status == "pending"
      assert ApiFlowStore.items() == %{"a" => 100, "b" => 200, "c" => 300}
    end

    test "a forged reject of an unknown id is reported", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)

      assert render_hook(view, "reject", %{"uuid" => UUIDv7.generate()}) =~ "not found"
    end

    test "an event nobody defined is refused", %{conn: conn} do
      {:ok, view, _html} = live(conn, @path)
      assert render_hook(view, "nope", %{}) =~ "not available"
    end

    test "a person who lost api since the page opened cannot decide", %{agent: _agent} do
      mine = admin_with_key()
      row = pending!(mine.agent)
      {:ok, view, _html} = live(log_in_user(build_conn(), mine.admin), @path)
      drop_api_silently!()

      html = render_hook(view, "reject", %{"uuid" => row.uuid})

      assert html =~ "not allowed"
      assert reload(row).status == "pending"
    end

    test "a person who lost api since the page opened cannot approve either", %{agent: _agent} do
      mine = admin_with_key()
      row = pending!(mine.agent)
      {:ok, view, _html} = live(log_in_user(build_conn(), mine.admin), @path)
      drop_api_silently!()

      html = render_hook(view, "approve", %{"uuid" => row.uuid})
      _ = render_async(view)

      assert html =~ "not allowed"
      assert reload(row).status == "pending"
      assert ApiFlowStore.items() == %{"a" => 100, "b" => 200, "c" => 300}
    end
  end

  describe "who may open the page" do
    test "an Admin without api is refused", %{} do
      {admin, _token} = create_admin_user()
      result = live(log_in_user(build_conn(), admin), @path)

      assert match?({:error, {kind, _}} when kind in [:redirect, :live_redirect], result)
    end

    test "an Admin who was granted api opens it", %{} do
      {admin, _token} = create_admin_user()
      {:ok, _} = Permissions.grant_permission(Roles.get_role_by_name("Admin").uuid, "api")

      assert {:ok, view, _html} = live(log_in_user(build_conn(), admin), @path)
      assert has_element?(view, "#approvals-page")
    end
  end
end
