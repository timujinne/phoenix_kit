defmodule PhoenixKit.Install.JsIntegrationThemeBootstrapTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Install.JsIntegration

  describe "theme_bootstrap_plan/1" do
    test "skips a layout that already renders the component" do
      html = """
      <head>
        <PhoenixKitWeb.Components.ThemeBootstrap.theme_bootstrap />
      </head>
      """

      assert JsIntegration.theme_bootstrap_plan(html) == :already_present
    end

    test "places the bootstrap after a stock phx:theme script, not before" do
      # phx.new 1.8's script treats "system" as "remove data-theme". Running
      # BEFORE it would stamp the configured pair and then have that undone.
      html = """
      <head>
        <script>
          localStorage.getItem("phx:theme")
        </script>
      </head>
      """

      assert JsIntegration.theme_bootstrap_plan(html) == :before_head_close
    end

    test "lands at the top of head when there is no stock script" do
      html = """
      <html>
        <head>
          <meta charset="utf-8" />
        </head>
      </html>
      """

      assert JsIntegration.theme_bootstrap_plan(html) == :top_of_head
    end

    test "a <header> is not a <head>" do
      # The previous injector used `<head[^>]*>`, which matches <header>.
      html = """
      <html>
        <body>
          <header class="nav"></header>
        </body>
      </html>
      """

      assert JsIntegration.theme_bootstrap_plan(html) == :top_of_head
    end
  end

  describe "inject_theme_bootstrap_into/1" do
    test "does not inject into a <header> when there is no <head>" do
      html = "<body><header class=\"nav\"></header></body>"
      assert JsIntegration.inject_theme_bootstrap_into(html) == html
    end

    test "injects after <head>, not after a later <header>" do
      html = """
      <head>
        <meta charset="utf-8" />
      </head>
      <body>
        <header>Nav</header>
      </body>
      """

      updated = JsIntegration.inject_theme_bootstrap_into(html)

      assert updated =~ ~r{<head>\s*<%!-- PhoenixKit theme bootstrap}
      refute String.contains?(updated, "<header>\n        <%!-- PhoenixKit theme bootstrap")
    end

    test "on a stock phx:theme layout, lands just before </head>" do
      html = """
      <head>
        <script>localStorage.getItem("phx:theme")</script>
      </head>
      """

      updated = JsIntegration.inject_theme_bootstrap_into(html)
      [before, _after] = String.split(updated, "</head>", parts: 2)

      assert before =~ "phx:theme"
      assert before =~ "ThemeBootstrap.theme_bootstrap"
    end
  end
end
