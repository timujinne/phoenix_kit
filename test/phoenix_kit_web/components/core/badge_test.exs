defmodule PhoenixKitWeb.Components.Core.BadgeTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias PhoenixKitWeb.Components.Core.Badge

  describe "status_badge/1" do
    test "derives the label from the status: underscores to spaces, capitalized" do
      html = render_component(&Badge.status_badge/1, status: "in_progress")
      assert html =~ "In progress"
      assert html =~ "badge-info"
    end

    test "label overrides the derived text but keeps the status colour" do
      html = render_component(&Badge.status_badge/1, status: "active", label: "Aktiivne")
      assert html =~ "Aktiivne"
      refute html =~ ">Active<"
      assert html =~ "badge-success"
    end

    test "label of nil falls back to the derived text" do
      html = render_component(&Badge.status_badge/1, status: "deleted", label: nil)
      assert html =~ "Deleted"
      assert html =~ "badge-error"
    end

    test "ending (still working, with an end set) is a warning" do
      html = render_component(&Badge.status_badge/1, status: "ending", label: "Ending")
      assert html =~ "badge-warning"
    end
  end
end
