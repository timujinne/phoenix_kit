defmodule PhoenixKitWeb.Components.Core.ButtonTest do
  @moduledoc """
  `button/1` had three defects that all present as "the attribute I passed did
  nothing":

  - `btn-primary` was hardcoded into the class list, so `class="btn-ghost"`
    left both on the element and daisyUI's rule ordering picked the winner;
  - `navigate` was not a declared attribute, so `<.button navigate={...}>` —
    which `table_default`'s own docs have shown for a while — silently dropped
    it and rendered a dead control;
  - `size` was undeclared for the same reason.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias PhoenixKitWeb.Components.Core.Button

  defp render_button(assigns) do
    assigns = Map.put_new(assigns, :inner_block, [%{inner_block: fn _, _ -> "Go" end}])
    render_component(&Button.button/1, assigns)
  end

  describe "status variants" do
    test "the status half of the palette renders its own colour class" do
      # Hosts previously fell back to raw <button> for delete buttons —
      # appending btn-error via class collided with the variant's colour.
      for {variant, class} <- [
            {"info", "btn-info"},
            {"success", "btn-success"},
            {"warning", "btn-warning"},
            {"error", "btn-error"}
          ] do
        assert render_button(%{variant: variant}) =~ class
      end
    end
  end

  describe "variant" do
    test "replaces the base colour rather than adding to it" do
      html = render_button(%{variant: "ghost"})

      assert html =~ "btn-ghost"
      refute html =~ "btn-primary"
    end

    test "defaults to primary" do
      assert render_button(%{}) =~ "btn-primary"
    end

    test "a caller class does not have to fight the default" do
      # The original failure mode: `class="btn-ghost"` with `btn-primary` still
      # present, and whichever daisyUI rule came last won.
      html = render_button(%{variant: "ghost", class: "w-full"})

      assert html =~ "btn-ghost"
      assert html =~ "w-full"
      refute html =~ "btn-primary"
    end
  end

  describe "size" do
    test "renders the daisyUI size class" do
      assert render_button(%{size: "sm"}) =~ "btn-sm"
    end

    test "omitting it adds no size class at all" do
      html = render_button(%{})

      refute html =~ "btn-xs"
      refute html =~ "btn-sm"
      refute html =~ "btn-md"
      refute html =~ "btn-lg"
    end
  end

  describe "navigation" do
    test "navigate renders a link, not a button" do
      html = render_button(%{navigate: "/admin/users"})

      assert html =~ ~s(href="/admin/users")
      refute html =~ "<button"
    end

    test "the documented table_default example now works" do
      # `<.button size="sm" navigate={~p"/users/…"}>` has been in the docs while
      # neither attribute existed.
      html = render_button(%{size: "sm", navigate: "/users/new"})

      assert html =~ ~s(href="/users/new")
      assert html =~ "btn-sm"
    end

    test "href renders a plain link" do
      assert render_button(%{href: "https://example.com"}) =~ ~s(href="https://example.com")
    end

    test "with no navigation attribute it is still a button" do
      html = render_button(%{type: "submit"})

      assert html =~ "<button"
      assert html =~ ~s(type="submit")
    end
  end

  describe "existing call sites" do
    test "a bare button renders the same shape as before" do
      html = render_button(%{})

      assert html =~ "btn"
      assert html =~ "btn-primary"
      assert html =~ "phx-submit-loading:opacity-75"
      assert html =~ "Go"
    end
  end
end
