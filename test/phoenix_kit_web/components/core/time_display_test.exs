defmodule PhoenixKitWeb.Components.Core.TimeDisplayTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.TimeDisplay

  @backend PhoenixKitWeb.Gettext

  setup do
    previous = Gettext.get_locale(@backend)
    on_exit(fn -> Gettext.put_locale(@backend, previous) end)
    :ok
  end

  defp ago(seconds) do
    DateTime.utc_now() |> DateTime.add(-seconds, :second) |> DateTime.truncate(:second)
  end

  defp render_ago(datetime, locale) do
    Gettext.put_locale(@backend, locale)
    assigns = %{datetime: datetime}
    rendered_to_string(~H|<.time_ago datetime={@datetime} />|)
  end

  defp text(html), do: html |> Floki.parse_fragment!() |> Floki.text() |> String.trim()

  @day 86_400

  describe "time_ago/1 text" do
    test "Russian picks the plural form of the count" do
      assert text(render_ago(ago(1 * @day + 60), "ru")) == "1 день назад"
      assert text(render_ago(ago(2 * @day + 60), "ru")) == "2 дня назад"
      assert text(render_ago(ago(5 * @day + 60), "ru")) == "5 дней назад"
      assert text(render_ago(ago(21 * @day + 60), "ru")) == "21 день назад"
    end

    test "Estonian picks the singular and the plural form" do
      assert text(render_ago(ago(1 * @day + 60), "et")) == "1 päev tagasi"
      assert text(render_ago(ago(3 * @day + 60), "et")) == "3 päeva tagasi"
    end

    test "every unit is translated, seconds included" do
      assert text(render_ago(ago(30), "et")) =~ ~r/^\d+ s tagasi$/
      assert text(render_ago(ago(5 * 60 + 5), "ru")) == "5 мин назад"
      assert text(render_ago(ago(3 * 3_600 + 5), "ru")) == "3 ч назад"
    end

    test "English keeps the short forms" do
      assert text(render_ago(ago(5 * 60 + 5), "en")) == "5m ago"
      assert text(render_ago(ago(2 * @day + 60), "en")) == "2d ago"
    end

    test "a NaiveDateTime is read as UTC" do
      naive = ago(2 * @day + 60) |> DateTime.to_naive()
      assert text(render_ago(naive, "ru")) == "2 дня назад"
    end

    test "a moment ahead of the clock reads as 0 seconds ago" do
      assert text(render_ago(ago(-3_600), "ru")) == "0 с назад"
      assert text(render_ago(ago(-3_600), "en")) == "0s ago"
    end

    test "nil renders a dash" do
      assert text(render_ago(nil, "ru")) == "—"
    end
  end

  describe "time_ago/1 markup" do
    test "is rendered by the server alone, with no client hook to rewrite it" do
      html = render_ago(ago(2 * @day), "ru")

      refute html =~ "phx-hook"
      refute html =~ "TimeAgo"
      assert html =~ "<time"
    end

    test "carries the machine-readable instant and the caller's id" do
      Gettext.put_locale(@backend, "en")
      assigns = %{datetime: ~U[2026-05-01 12:00:00Z]}

      html = rendered_to_string(~H|<.time_ago datetime={@datetime} id="created-at" />|)

      assert html =~ ~s(datetime="2026-05-01T12:00:00Z")
      assert html =~ ~s(id="created-at")
    end

    test "the title has no English month name" do
      html = render_ago(~U[2026-05-01 12:00:00Z], "ru")
      [title] = html |> Floki.parse_fragment!() |> Floki.attribute("time", "title")

      refute title =~ ~r/[A-Za-z]{3,}/
      assert title =~ "2026"
    end
  end
end
