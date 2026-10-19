defmodule PhoenixKit.Integration.Utils.DateNavFormatTest do
  @moduledoc """
  The day picker's width follows the site's date format: "September 30, 2026"
  (`F j, Y`) does not fit the width that "30.09.2026" does.
  """

  use PhoenixKit.DataCase, async: false

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.DateNav

  alias PhoenixKit.Settings

  # The setting is read through the cache, which a write invalidates only by
  # cast and which outlives the sandbox rollback: evict it synchronously.
  defp put_format(format) do
    {:ok, _} = Settings.update_setting("date_format", format)
    PhoenixKit.Cache.invalidate_now(:settings, ["date_format"])
  end

  setup do
    on_exit(fn -> PhoenixKit.Cache.invalidate_now(:settings, ["date_format"]) end)
  end

  defp picker_classes do
    assigns = %{}

    html =
      rendered_to_string(~H"""
      <.date_nav date={~D[2026-09-30]} today={~D[2026-09-30]} path={&"/stats?date=#{&1}"} />
      """)

    [class] =
      Regex.run(~r/<input[^>]*data-date-text[^>]*class="([^"]*)"/, html, capture: :all_but_first)

    String.split(class)
  end

  test "a textual month gets a wider picker" do
    put_format("F j, Y")
    classes = picker_classes()
    assert "w-52" in classes
    refute "w-38" in classes
  end

  test "numeric formats keep the narrow picker" do
    for format <- ["Y-m-d", "m/d/Y", "d/m/Y", "d.m.Y", "d-m-Y"] do
      put_format(format)
      classes = picker_classes()
      assert "w-38" in classes, format
      refute "w-52" in classes, format
    end
  end
end
