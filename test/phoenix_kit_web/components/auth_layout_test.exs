defmodule PhoenixKitWeb.Components.AuthLayoutTest do
  @moduledoc """
  Auth pages used to render inside the host's `Layouts.app`, which on a stock
  `mix phx.new` app is where the Phoenix logo, framework version and off-site
  links live — so every kit install shipped Phoenix Framework branding on its
  login page. Admin never did this; auth was the outlier.

  These assert against a **host-shaped** layout fixture on purpose. Core's own
  dev/test app configures no layout at all, so an assertion written against it
  would pass no matter which path the component took.
  """
  use PhoenixKit.DataCase, async: false

  import Phoenix.LiveViewTest

  alias PhoenixKitWeb.Components.AuthPageWrapper

  defmodule HostLayouts do
    @moduledoc false
    use Phoenix.Component

    # Stands in for the chrome a phx.new app puts in its :app layout.
    def app(assigns) do
      ~H"""
      <div id="host-app-chrome">
        <a href="https://phoenixframework.org">Phoenix Framework v1.8</a>
        {render_slot(@inner_block)}
      </div>
      """
    end
  end

  setup do
    previous = {
      Application.get_env(:phoenix_kit, :layouts_module),
      Application.get_env(:phoenix_kit, :phoenix_version_strategy),
      Application.get_env(:phoenix_kit, :auth_uses_host_layout)
    }

    Application.put_env(:phoenix_kit, :layouts_module, HostLayouts)
    Application.put_env(:phoenix_kit, :phoenix_version_strategy, :modern)

    on_exit(fn ->
      {layouts, strategy, opt_in} = previous
      restore(:layouts_module, layouts)
      restore(:phoenix_version_strategy, strategy)
      restore(:auth_uses_host_layout, opt_in)
    end)

    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore(key, value), do: Application.put_env(:phoenix_kit, key, value)

  defp render_auth_page do
    render_component(&AuthPageWrapper.auth_page_wrapper/1, %{
      flash: %{},
      page_title: "Log in",
      inner_block: [%{inner_block: fn _, _ -> "SIGN IN FORM" end}]
    })
  end

  describe "by default" do
    test "the host's app chrome does not wrap the sign-in page" do
      html = render_auth_page()

      refute html =~ "host-app-chrome"
      refute html =~ "Phoenix Framework"
      assert html =~ "SIGN IN FORM"
    end
  end

  describe "with auth_uses_host_layout: true" do
    test "the host gets its chrome back" do
      # The documented opt-in for a host that genuinely wants its own header on
      # sign-in. Unset is the new default, rather than a knob that changes the
      # default as a side effect of existing.
      Application.put_env(:phoenix_kit, :auth_uses_host_layout, true)

      html = render_auth_page()

      assert html =~ "host-app-chrome"
      assert html =~ "SIGN IN FORM"
    end
  end

  describe "viewport math" do
    test "carries no viewport-unit width or height" do
      # `w-[100vw]` overflowed by exactly the scrollbar-gutter width, because
      # the host root reserves the gutter unconditionally — a horizontal
      # scrollbar on a page with nothing to scroll. `100vh` is the same bug
      # class vertically, and on mobile it is the LARGE viewport, which hides
      # the bottom of the card behind the URL bar.
      html = render_auth_page()

      refute html =~ "100vw"
      refute html =~ "100vh"
      refute html =~ "50vw"
    end

    test "never reintroduces a scrollbar-gutter override" do
      # Core removed every one of these in 2026-07 and the standing rule is not
      # to add them back — daisyUI handles the gutter.
      refute render_auth_page() =~ "scrollbar-gutter"
    end
  end
end
