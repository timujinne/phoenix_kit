defmodule PhoenixKitWeb.Components.Core.ChartTest do
  @moduledoc """
  These charts are server-rendered SVG, so the rendered markup IS the
  output — geometry bugs are assertable without a browser.

  The invariants worth protecting: never crash on the shapes real data
  actually takes (empty, one point, flat, negative, huge), and never emit
  SVG a browser will silently drop (negative `height`, `NaN` coordinates).
  """
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.Chart

  # ~H expands where it is written and needs an `assigns` variable in scope.
  # These components take no assigns of their own, so each test binds an empty
  # map.
  defp render(template), do: rendered_to_string(template)

  # Every numeric attribute a browser parses. A stray NaN/Infinity makes the
  # whole element vanish, so scan the actual attribute values rather than
  # eyeballing the path string.
  defp numeric_attrs(html) do
    # The leading space matters: without it `viewBox="0 0 960 240"` matches as
    # `x="..."`, because "viewBox" ends in an x.
    ~r/\s(?:x|y|x1|y1|x2|y2|width|height|rx)="([^"]*)"/
    |> Regex.scan(html)
    |> Enum.map(&List.last/1)
  end

  defp path_numbers(html) do
    ~r/[ML]([-\d.eE+]+),([-\d.eE+]+)/
    |> Regex.scan(html)
    |> Enum.flat_map(fn [_, x, y] -> [x, y] end)
  end

  # The `d` of the path that actually carries the stroke — the area fill path
  # always contains an L (it closes to the baseline), so matching on any path
  # would pass even when the line is a bare moveto that paints nothing.
  defp stroked_path(html) do
    case Regex.run(~r/<path[^>]*\sd="([^"]*)"[^>]*stroke="currentColor"/, html) do
      [_, d] -> d
      _ -> ""
    end
  end

  # Coordinates far outside the viewBox mean the chart is invisible even though
  # the numbers are technically finite.
  defp assert_within_viewbox(html, width, height) do
    limit = max(width, height) * 10

    for value <- path_numbers(html) do
      {n, ""} = Float.parse(value)

      assert abs(n) <= limit,
             "coordinate #{n} is far outside the #{width}x#{height} viewBox"
    end
  end

  # A polyline's coordinates live in `points="…"`, which contributes neither an
  # x/y attribute nor an M/L command — so the sparkline assertions used to
  # iterate an empty list and would have passed with points="NaN,NaN".
  defp polyline_numbers(html) do
    case Regex.run(~r/<polyline[^>]*\spoints="([^"]*)"/, html) do
      [_, pts] -> pts |> String.split([" ", ","], trim: true)
      _ -> []
    end
  end

  # A path whose points all coincide is syntactically a path and visually
  # nothing at all — which is exactly how a broken single-point chart passed.
  # A dot counts: it is what a lone point renders as, and it paints.
  defp assert_visible_mark(html) do
    points =
      stroked_path(html)
      |> then(&Regex.scan(~r/[ML]([-\d.eE+]+),([-\d.eE+]+)/, &1))
      |> Enum.map(fn [_, x, y] -> {x, y} end)
      |> Enum.uniq()

    assert length(points) > 1 or html =~ "<circle",
           "nothing is painted: the path collapses to #{inspect(points)} and there is no dot"
  end

  # A dot placed off-canvas paints nothing either, so single-point charts have
  # to prove the mark is where a viewer can see it.
  defp assert_dot_within_viewbox(html, width, height) do
    [_, cx, cy] = Regex.run(~r/<circle[^>]*cx="([\d.-]+)"[^>]*cy="([\d.-]+)"/, html)
    {cx, ""} = Float.parse(cx)
    {cy, ""} = Float.parse(cy)

    assert cx >= 0 and cx <= width and cy >= 0 and cy <= height,
           "the dot sits at #{cx},#{cy}, outside the #{width}x#{height} viewBox"
  end

  # A rect outside the viewBox is clipped away, so "height > 0" is not the same
  # as "visible" — the hairline floor pushed zero bars to height..height+1.
  defp assert_bars_within_viewbox(html, view_height) do
    rects = Regex.scan(~r/\sy="([\d.-]+)" width="[\d.]+" height="([\d.]+)"/, html)
    assert rects != [], "no bars found"

    for [_, y, h] <- rects do
      {y, ""} = Float.parse(y)
      {h, ""} = Float.parse(h)

      assert y >= 0 and y + h <= view_height,
             "bar spans #{y}..#{y + h}, outside the 0..#{view_height} viewBox"
    end
  end

  defp assert_finite_numbers(html) do
    values = numeric_attrs(html) ++ path_numbers(html) ++ polyline_numbers(html)

    # Scanning the raw html catches non-finite output the number regexes skip
    # over: `[-\d.eE+]` never matches "NaN", so a NaN coordinate simply
    # vanished from the list instead of failing.
    refute html =~ ~r/\b(nan|infinity)\b/i, "non-finite number in rendered SVG"
    assert values != [], "no numbers found — the assertion would pass vacuously"

    for value <- values do
      case Float.parse(value) do
        {_, ""} -> :ok
        _ -> flunk("unparseable number in rendered SVG: #{inspect(value)}")
      end
    end
  end

  describe "line_chart/1" do
    test "renders a line path for a simple series" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {1, 5}, {2, 3}]} />|)

      assert html =~ "<svg"
      assert html =~ ~s(stroke="currentColor")
      assert stroked_path(html) =~ ~r/^M[\d.]+,[\d.]+ L/
      assert_finite_numbers(html)
    end

    test "empty data renders the :empty slot and no svg" do
      assigns = %{}

      html =
        render(~H"""
        <.line_chart id="c" data={[]}>
          <:empty>Nothing to show</:empty>
        </.line_chart>
        """)

      assert html =~ "Nothing to show"
      refute html =~ "<svg"
    end

    test "empty data without an :empty slot renders nothing rather than crashing" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[]} />|)

      refute html =~ "<svg"
    end

    test "a single point does not crash and still draws something visible" do
      assigns = %{}

      # A lone "M x,y" is a valid path that paints NOTHING. Interval data of
      # length one is a real case (first slot of the day), so it has to
      # produce a visible mark.
      html = render(~H|<.line_chart id="c" data={[{5, 10}]} />|)

      assert html =~ "<svg"
      assert_finite_numbers(html)

      # Assert the OUTCOME, not the shape of the markup: `M0,120 L0,120`
      # satisfies a "has a segment" regex perfectly and paints nothing at all.
      assert_visible_mark(html)
      assert_dot_within_viewbox(html, 960, 240)
    end

    test "a single point is visible under the default (auto) domain too" do
      assigns = %{}

      # The auto domain collapses x_min == x_max, so every x maps to 0 — the
      # configuration nearly every caller uses was the one that stayed blank.
      for opts <- [%{}, %{step: true}] do
        assigns = Map.merge(assigns, opts)

        html =
          if assigns[:step] do
            render(~H|<.line_chart id="c" data={[{5, 3}]} step />|)
          else
            render(~H|<.line_chart id="c" data={[{5, 3}]} />|)
          end

        assert_visible_mark(html)
        # A collapsed domain has no left or right, so the mark belongs at the
        # centre — pinned to x=0 half its stroke falls outside the viewBox.
        assert_dot_within_viewbox(html, 960, 240)
      end
    end

    test "two points sharing an x keep both values" do
      # Widening a collapsed x-span into a full-width horizontal line kept only
      # the first y and silently dropped the second — a plausible-looking flat
      # line with half the data missing, and no :empty slot to signal it.
      assigns = %{}
      html = render(~H|<.line_chart id="c" data={[{5, 10}, {5, 90}]} y_domain={{0, 100}} />|)

      ys =
        stroked_path(html)
        |> then(&Regex.scan(~r/[ML][\d.-]+,([\d.-]+)/, &1))
        |> Enum.map(fn [_, y] -> y end)
        |> Enum.uniq()

      assert length(ys) == 2, "both values must be plotted, got #{inspect(ys)}"
    end

    test "a series with a small range on a huge baseline still shows its shape" do
      # Padding by a fraction of the MAGNITUDE swamped the range: 1.0e12-scale
      # counters differing by 100 flattened onto one row of pixels.
      assigns = %{}

      html =
        render(
          ~H|<.line_chart id="c" data={[{0, 1.0e12}, {1, 1.0e12 + 50}, {2, 1.0e12 + 100}]} />|
        )

      ys =
        stroked_path(html)
        |> then(&Regex.scan(~r/[ML][\d.-]+,([\d.-]+)/, &1))
        |> Enum.map(fn [_, y] -> y end)
        |> Enum.uniq()

      assert length(ys) > 1, "real variation collapsed to a flat line: #{inspect(ys)}"
    end

    test "a datum outside an explicit domain is not painted across the chart" do
      # Widening a zero-length path asserted the value across the whole domain
      # for a sample that is not in it. Out-of-domain data belongs off-canvas.
      assigns = %{}
      html = render(~H|<.line_chart id="c" data={[{150, 5}]} step x_domain={{0, 100}} />|)

      [_, cx] = Regex.run(~r/<circle[^>]*cx="([\d.-]+)"/, html)
      {cx, ""} = Float.parse(cx)

      assert cx > 960, "an out-of-domain point was drawn inside the viewBox at #{cx}"
    end

    test "values at the float ceiling do not crash the render" do
      assigns = %{}

      assert render(~H|<.line_chart id="c" data={[{0, 1.7976931348623157e308}]} />|) =~ "<svg"
    end

    test "negative values render finite geometry" do
      assigns = %{}

      # Electricity prices go negative; this must not produce NaN or invert.
      html = render(~H|<.line_chart id="c" data={[{0, -40}, {1, -10}, {2, 25}]} />|)

      assert_finite_numbers(html)
    end

    test "a completely flat series renders finite geometry" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 7}, {1, 7}, {2, 7}]} />|)

      assert_finite_numbers(html)
    end

    test "an explicit zero-span y_domain does not divide by zero" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 5}, {1, 5}]} y_domain={{5, 5}} />|)

      assert_finite_numbers(html)
    end

    test "step mode holds each y until the next x" do
      assigns = %{}

      html =
        render(~H|<.line_chart id="c" data={[{0, 0}, {10, 100}]} step y_domain={{0, 100}} />|)

      # Compare against the SAME data without `step`: the stepped line must
      # carry strictly more vertices. A bare count passed even with step
      # removed, because path_numbers also scans the area path.
      plain = render(~H|<.line_chart id="c" data={[{0, 0}, {10, 100}]} y_domain={{0, 100}} />|)

      stepped_points = stroked_path(html) |> String.split("L") |> length()
      plain_points = stroked_path(plain) |> String.split("L") |> length()

      assert stepped_points > plain_points
      assert_finite_numbers(html)
    end

    test "step mode extends the final slot to the x domain's right edge" do
      assigns = %{}

      html =
        render(
          ~H|<.line_chart id="c" data={[{0, 1}, {5, 2}]} step x_domain={{0, 10}} width={100} />|
        )

      # The last slot must reach the domain edge (x=100 in viewBox units),
      # not stop at the last data x (x=50).
      assert html =~ ~r/L100(?:\.0)?,/
      assert_finite_numbers(html)
    end

    test "marker_x inside the domain renders a dashed marker" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {10, 2}]} marker_x={5} />|)

      assert html =~ ~s(stroke-dasharray="4 4")
    end

    test "marker_x outside the domain is omitted" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {10, 2}]} marker_x={99} />|)

      refute html =~ ~s(stroke-dasharray="4 4")
    end

    test "gridlines={0} disables gridlines" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {1, 2}]} gridlines={0} />|)

      refute html =~ ~s(stroke-opacity="0.08")
    end

    test "area={false} omits the filled path" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {1, 2}]} area={false} />|)

      refute html =~ "url(#c-fill)"
    end

    test "the gradient id is namespaced by the component id" do
      assigns = %{}

      # Two charts on one page must not share a gradient def.
      html = render(~H|<.line_chart id="left" data={[{0, 1}, {1, 2}]} />|)

      assert html =~ ~s(id="left-fill")
      assert html =~ "url(#left-fill)"
    end

    test "float data renders finite geometry" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0.0, 1.5}, {1.25, 2.75}]} />|)

      assert_finite_numbers(html)
    end

    test "a reversed x_domain is normalised rather than exploding off-canvas" do
      assigns = %{}
      # {10, 0} used to drive the span negative; the 1.0e-9 floor then produced
      # coordinates around 1.0e12 and the chart simply vanished.
      html = render(~H|<.line_chart id="c" data={[{0, 1}, {10, 2}]} x_domain={{10, 0}} />|)

      assert_finite_numbers(html)
      assert_within_viewbox(html, 960, 240)
    end

    test "a reversed y_domain is normalised rather than exploding off-canvas" do
      assigns = %{}
      html = render(~H|<.line_chart id="c" data={[{0, 1}, {10, 2}]} y_domain={{5, 0}} />|)

      assert_finite_numbers(html)
      assert_within_viewbox(html, 960, 240)
    end

    test "unsorted data is drawn left-to-right" do
      assigns = %{}
      # Unsorted input rendered as a zigzag that reads like a chart bug.
      html = render(~H|<.line_chart id="c" data={[{5, 1}, {0, 9}, {10, 2}]} />|)

      xs =
        stroked_path(html)
        |> then(&Regex.scan(~r/[ML]([-\d.eE+]+),/, &1))
        |> Enum.map(fn [_, x] -> elem(Float.parse(x), 0) end)

      assert xs == Enum.sort(xs), "points must be drawn in ascending x order, got: #{inspect(xs)}"
    end

    test "carries an accessible name" do
      assigns = %{}

      html = render(~H|<.line_chart id="c" data={[{0, 1}, {1, 2}]} aria_label="Prices today" />|)

      # role="img" without a name is an unlabelled graphic to a screen reader.
      assert html =~ "Prices today"
    end
  end

  describe "round-2 regressions" do
    test "a partially-unusable domain falls back to the data, not a constant" do
      assigns = %{}
      # A {0, 1} fallback recreated the reversed-domain bug: every real x range
      # then scaled by thousands and left the canvas just as finally.
      html =
        render(
          ~H|<.line_chart id="c" data={[{0, 1}, {720, 5}, {1440, 3}]} x_domain={{0, nil}} />|
        )

      assert_finite_numbers(html)
      assert_within_viewbox(html, 960, 240)
    end

    test "an entirely unusable domain also falls back to the data" do
      assigns = %{}
      html = render(~H|<.line_chart id="c" data={[{0, 1}, {1440, 3}]} x_domain="nonsense" />|)

      assert_within_viewbox(html, 960, 240)
    end

    test "step data overshooting its x_domain does not double back" do
      assigns = %{}
      # The tail used to emit the viewBox width unconditionally, so the line ran
      # forward past the edge and then back leftward.
      html = render(~H|<.line_chart id="c" data={[{0, 1}, {20, 5}]} x_domain={{0, 10}} step />|)

      xs =
        stroked_path(html)
        |> then(&Regex.scan(~r/[ML]([-\d.eE+]+),/, &1))
        |> Enum.map(fn [_, x] -> elem(Float.parse(x), 0) end)

      assert xs == Enum.sort(xs), "the line must not run backwards: #{inspect(xs)}"
    end

    test "dropping a sparkline sample leaves a gap instead of reshaping the line" do
      assigns = %{}
      # Rejecting before indexing re-spaced the axis, so removing one bad
      # sample silently changed the SHAPE of the line rather than the gap.
      with_hole = render(~H|<.sparkline values={[1, 2, nil, 4, 5]} />|)
      without = render(~H|<.sparkline values={[1, 2, 3, 4, 5]} />|)

      xs = fn html ->
        [_, pts] = Regex.run(~r/points="([^"]*)"/, html)
        pts |> String.split(" ") |> Enum.map(&(&1 |> String.split(",") |> hd()))
      end

      # The survivors keep the x positions they had in the full series.
      assert xs.(with_hole) == xs.(without) -- ["100.0"]
    end

    test "large-magnitude flat series keep their padding" do
      # An absolute 1.0e-9 pad is below one ULP past ~1e7, so the 10% padding
      # evaporated and the series sank onto the axis with its stroke clipped.
      assigns = %{}
      html = render(~H|<.sparkline values={[3.0e7, 3.0e7, 3.0e7]} />|)

      [_, pts] = Regex.run(~r/points="([^"]*)"/, html)

      {y, ""} =
        pts |> String.split(" ") |> hd() |> String.split(",") |> List.last() |> Float.parse()

      assert y > 8 and y < 40, "large flat series should still centre, got y=#{y}"
    end

    test "a flat sparkline centres rather than sitting on the floor" do
      assigns = %{}
      html = render(~H|<.sparkline values={[3, 3, 3]} />|)

      [_, pts] = Regex.run(~r/points="([^"]*)"/, html)
      ys = pts |> String.split(" ") |> Enum.map(&(&1 |> String.split(",") |> List.last()))
      {y, ""} = ys |> hd() |> Float.parse()

      # A steady metric reading as "at its minimum" is a lie about the data.
      assert y > 8 and y < 40, "flat series should sit mid-box, got y=#{y}"
    end
  end

  describe "data normalisation" do
    test "one bad point never takes the page down" do
      # A library primitive that raises mid-render kills the whole LiveView.
      # Ecto hands callers Decimals; JSON hands them nils and strings.
      assigns = %{}

      for bad <- [nil, "12", :atom, %{}] do
        assigns = Map.put(assigns, :bad, bad)

        html =
          render(~H|<.line_chart id="c" data={[{0, 1}, {1, @bad}, {2, 3}]} />|)

        assert html =~ "<svg"
        assert_finite_numbers(html)
      end
    end

    test "Decimal values are plotted, not crashed on" do
      assigns = %{
        data: [{0, Decimal.new("1.5")}, {1, Decimal.new("2.75")}, {Decimal.new("2"), 3}]
      }

      html = render(~H|<.line_chart id="c" data={@data} />|)

      assert html =~ "<svg"
      assert_finite_numbers(html)
    end

    test "points may be maps as well as tuples" do
      assigns = %{data: [%{x: 0, y: 1}, %{x: 1, y: 5}]}

      html = render(~H|<.line_chart id="c" data={@data} />|)

      assert html =~ "<svg"
      assert_finite_numbers(html)
    end

    test "string-keyed maps work too" do
      assigns = %{data: [%{"x" => 0, "y" => 1}, %{"x" => 1, "y" => 5}]}

      assert render(~H|<.line_chart id="c" data={@data} />|) =~ "<svg"
    end

    test "when nothing is usable the :empty slot renders" do
      assigns = %{}

      html =
        render(~H"""
        <.line_chart id="c" data={[{nil, nil}, {"a", "b"}]}>
          <:empty>No usable data</:empty>
        </.line_chart>
        """)

      assert html =~ "No usable data"
      refute html =~ "<svg"
    end

    test "bar data missing :value is dropped rather than raising" do
      assigns = %{data: [%{label: "a"}, %{label: "b", value: 5}]}

      html = render(~H|<.bar_chart id="b" data={@data} />|)

      assert length(Regex.scan(~r/<rect/, html)) == 1
    end

    test "a non-numeric marker_x is ignored" do
      assigns = %{}
      html = render(~H|<.line_chart id="c" data={[{0, 1}, {10, 2}]} marker_x="noon" />|)

      refute html =~ ~s(stroke-dasharray="4 4")
    end
  end

  describe "bar_chart extras" do
    test "each bar carries a native title tooltip" do
      assigns = %{}

      html =
        render(~H|<.bar_chart id="b" data={[%{label: "Mon", value: 12}]} />|)

      assert html =~ "<title>Mon: 12</title>"
    end

    test "a small magnitude is not rounded away to zero" do
      # 4dp rounding turned a rate or a sub-cent price into "0".
      assigns = %{data: [%{label: "rate", value: 1.234e-5}]}

      html = render(~H|<.bar_chart id="b" data={@data} />|)

      refute html =~ "<title>rate: 0</title>"
    end

    test "value_format takes over the tooltip entirely" do
      assigns = %{
        data: [%{label: "power", value: 1234}],
        fmt: fn v -> "#{v} kWh" end
      }

      assert render(~H|<.bar_chart id="b" data={@data} value_format={@fmt} />|) =~
               "<title>power: 1234 kWh</title>"
    end

    test "a raising value_format falls back rather than crashing the page" do
      assigns = %{data: [%{label: "x", value: 1}], fmt: fn _ -> raise "boom" end}

      assert render(~H|<.bar_chart id="b" data={@data} value_format={@fmt} />|) =~ "<title>x: 1"
    end

    test "bars accept tuples and string-keyed maps, like line_chart's points" do
      assigns = %{
        tuples: [{"Mon", 5}, {"Tue", 8}],
        strings: [%{"label" => "Mon", "value" => 5}]
      }

      assert render(~H|<.bar_chart id="b" data={@tuples} />|) =~ "<rect"
      assert render(~H|<.bar_chart id="b" data={@strings} />|) =~ "<rect"
    end

    test "an all-negative series still draws its zero line" do
      assigns = %{}
      # The baseline sits at the TOP there, which nothing else implies.
      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: -3}, %{label: "b", value: -8}]} />|
        )

      assert html =~ ~s(stroke-opacity="0.25")
    end

    test "an all-zero series still renders visible categories" do
      assigns = %{}
      # Zero-height rects paint nothing, so valid data produced a blank chart.
      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: 0}, %{label: "b", value: 0}]} />|
        )

      # `height > 0` was true the whole time — the rect was simply drawn just
      # below the viewBox and clipped away.
      assert_bars_within_viewbox(html, 200)
    end

    test "tooltip values are formatted for humans, not float noise" do
      # A computed value like 0.1 + 0.2 renders as 0.30000000000000004
      # unformatted, which is what a tooltip would have shown.
      assigns = %{
        data: [
          %{label: "computed", value: 0.1 + 0.2},
          %{label: "whole", value: 12.0},
          %{label: "int", value: 7},
          %{label: "money", value: Decimal.new("12.30")}
        ]
      }

      html = render(~H|<.bar_chart id="b" data={@data} />|)

      assert html =~ "<title>computed: 0.3</title>"
      assert html =~ "<title>whole: 12</title>"
      assert html =~ "<title>int: 7</title>"
      assert html =~ "<title>money: 12.3</title>"
    end

    test "a label without String.Chars does not crash the render" do
      # `:label` is documented as `term` and the tuple form accepts anything,
      # so interpolating it raised Protocol.UndefinedError and took the page
      # down over a label.
      assigns = %{data: [%{label: {:a, :b}, value: 1}, %{label: %{k: 1}, value: 2}]}

      assert render(~H|<.bar_chart id="b" data={@data} />|) =~ "<rect"
    end

    test "a small negative among large positives stays inside the viewBox" do
      # The baseline lands ON the bottom edge here, so a hairline hung from it
      # spanned height..height+1 — clipped away, and the datum vanished.
      assigns = %{data: [%{label: "a", value: 1.0e6}, %{label: "b", value: -1}]}

      assert_bars_within_viewbox(render(~H|<.bar_chart id="b" data={@data} />|), 200)
    end

    test "a visible label without String.Chars does not crash the render" do
      # The tooltip path was guarded but the rendered label was not, so
      # show_labels turned the same bad datum back into a page crash.
      assigns = %{data: [%{label: [date: "2026-07-29"], value: 5}]}

      assert render(~H|<.bar_chart id="b" data={@data} show_labels />|) =~ "<rect"
    end

    test "a per-datum class colours a single bar" do
      assigns = %{data: [%{label: "a", value: 1}, %{label: "b", value: 2, class: "text-error"}]}

      assert render(~H|<.bar_chart id="b" data={@data} />|) =~ "text-error"
    end

    test "the zero baseline is drawn only when the data spans both signs" do
      assigns = %{}

      mixed =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: -1}, %{label: "b", value: 2}]} />|
        )

      positive =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: 1}, %{label: "b", value: 2}]} />|
        )

      assert mixed =~ ~s(stroke-opacity="0.25")
      refute positive =~ ~s(stroke-opacity="0.25")
    end

    test "the svg carries the given id" do
      assigns = %{}

      assert render(~H|<.bar_chart id="daily" data={[%{label: "a", value: 1}]} />|) =~
               ~s(id="daily")
    end

    test "labels are sized to their bar's slot, not spread edge-to-edge" do
      # `justify-between` pinned the first and last labels to the container
      # edges while the bars sit at slot centres.
      assigns = %{data: Enum.map(1..3, &%{label: "d#{&1}", value: &1})}

      html = render(~H|<.bar_chart id="b" data={@data} show_labels />|)

      assert html =~ "width: 33.3%"
      refute html =~ "justify-between"
    end
  end

  describe "sparkline/1" do
    test "renders a polyline for a list of values" do
      assigns = %{}

      html = render(~H|<.sparkline values={[1, 5, 2, 8]} />|)

      assert html =~ "<polyline"
      assert_finite_numbers(html)
    end

    test "a zero value among positives stays inside the viewBox" do
      assigns = %{}

      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: 0}, %{label: "b", value: 5}]} />|
        )

      assert_bars_within_viewbox(html, 200)
    end

    test "a single value draws a flat line rather than an empty box" do
      # One sample is a real state; rendering nothing reads as a broken chart.
      assigns = %{}
      html = render(~H|<.sparkline values={[7]} />|)

      assert html =~ "<polyline"
      assert_finite_numbers(html)
    end

    test "no usable values renders the :empty slot" do
      assigns = %{}

      html =
        render(~H"""
        <.sparkline values={[]}>
          <:empty>No trend</:empty>
        </.sparkline>
        """)

      assert html =~ "No trend"
      refute html =~ "<polyline"
    end

    test "identical values render finite geometry" do
      assigns = %{}

      html = render(~H|<.sparkline values={[3, 3, 3]} />|)

      assert_finite_numbers(html)
    end

    test "negative values render finite geometry" do
      assigns = %{}

      html = render(~H|<.sparkline values={[-5, -1, -9]} />|)

      assert_finite_numbers(html)
    end
  end

  describe "bar_chart/1" do
    test "renders one rect per datum" do
      assigns = %{}

      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: 1}, %{label: "b", value: 2}]} />|
        )

      assert length(Regex.scan(~r/<rect/, html)) == 2
      assert_finite_numbers(html)
    end

    test "empty data renders the :empty slot" do
      assigns = %{}

      html =
        render(~H"""
        <.bar_chart id="b" data={[]}>
          <:empty>No bars</:empty>
        </.bar_chart>
        """)

      assert html =~ "No bars"
      refute html =~ "<rect"
    end

    test "negative values never produce a negative rect height" do
      assigns = %{}

      # SVG drops a rect with negative height entirely — the bar silently
      # disappears instead of rendering below a baseline.
      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: -5}, %{label: "b", value: 10}]} />|
        )

      for [_, h] <- Regex.scan(~r/height="([^"]*)"/, html) do
        {value, ""} = Float.parse(h)
        assert value >= 0, "negative rect height would render nothing: #{h}"
      end

      assert_bars_within_viewbox(html, 200)
      assert_finite_numbers(html)
    end

    test "all-zero values render finite geometry" do
      assigns = %{}

      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: 0}, %{label: "b", value: 0}]} />|
        )

      assert_finite_numbers(html)
    end

    test "all-negative values render finite geometry" do
      assigns = %{}

      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "a", value: -3}, %{label: "b", value: -8}]} />|
        )

      assert_finite_numbers(html)
    end

    test "show_labels renders one label per bar" do
      assigns = %{}

      html =
        render(
          ~H|<.bar_chart id="b" data={[%{label: "Mon", value: 1}, %{label: "Tue", value: 2}]} show_labels />|
        )

      assert html =~ "Mon"
      assert html =~ "Tue"
    end
  end

  describe "y_invert — rank-like data" do
    test "smaller values plot HIGHER on the line chart" do
      # Search position 1 is the best result and belongs at the top. Without
      # this, callers negated their own data, which flipped the sign of every
      # domain and marker they passed too.
      assigns = %{}

      normal =
        render(~H"""
        <.line_chart id="n" data={[{0, 1}, {1, 10}]} height={100} />
        """)

      inverted =
        render(~H"""
        <.line_chart id="i" data={[{0, 1}, {1, 10}]} height={100} y_invert />
        """)

      assert [_, ny0, ny1] = Regex.run(~r/M[\d.]+,([\d.]+) L[\d.]+,([\d.]+)/, normal)
      assert [_, iy0, iy1] = Regex.run(~r/M[\d.]+,([\d.]+) L[\d.]+,([\d.]+)/, inverted)

      # SVG y grows downward: "higher" is a SMALLER y.
      assert elem(Float.parse(ny0), 0) > elem(Float.parse(ny1), 0)
      assert elem(Float.parse(iy0), 0) < elem(Float.parse(iy1), 0)
    end

    test "the sparkline inverts too" do
      assigns = %{}

      normal = render(~H|<.sparkline values={[1, 10]} height={48} />|)
      inverted = render(~H|<.sparkline values={[1, 10]} height={48} y_invert />|)

      assert [_, ny0, ny1] = Regex.run(~r/points="[\d.]+,([\d.]+) [\d.]+,([\d.]+)"/, normal)
      assert [_, iy0, iy1] = Regex.run(~r/points="[\d.]+,([\d.]+) [\d.]+,([\d.]+)"/, inverted)

      assert elem(Float.parse(ny0), 0) > elem(Float.parse(ny1), 0)
      assert elem(Float.parse(iy0), 0) < elem(Float.parse(iy1), 0)
    end

    test "inverted charts stay inside the viewBox" do
      assigns = %{}

      html =
        render(~H"""
        <.line_chart id="b" data={[{0, 1}, {1, 50}, {2, 3}]} height={100} y_invert />
        """)

      # round1 drops a trailing ".0", so coordinates arrive as "100" as well
      # as "99.5" — parse both.
      ys =
        Regex.scan(~r/[ML][\d.]+,([\d.]+)/, html)
        |> Enum.map(fn [_, y] -> elem(Float.parse(y), 0) end)

      assert ys != []
      assert Enum.all?(ys, &(&1 >= 0.0 and &1 <= 100.0))
    end
  end

  describe "stacked bars" do
    test "JSON-decoded stacked data renders the same bars and tooltips" do
      data = [
        %{
          label: "Mon",
          parts: [
            %{label: "Ada", value: 3, class: "text-primary"},
            %{label: "Bot", value: 1, class: "text-secondary"}
          ]
        }
      ]

      assigns = %{data: data}
      expected = render(~H|<.bar_chart id="json-stack" data={@data} />|)
      assigns = %{data: data |> JSON.encode!() |> JSON.decode!()}

      assert render(~H|<.bar_chart id="json-stack" data={@data} />|) == expected
    end

    test "a datum with parts is one bar of a rect per part, under one tooltip" do
      assigns = %{
        data: [
          %{
            label: "Mon",
            parts: [
              %{label: "Ada", value: 120, class: "text-primary"},
              %{label: "Bot", value: 60, class: "text-secondary"},
              %{label: "Nil", value: 0, class: "text-error"}
            ]
          }
        ]
      }

      html = render(~H|<.bar_chart id="b" data={@data} />|)

      [group] = Regex.run(~r/<g>\s*<title>.*?<\/g>/s, html)
      assert group =~ "text-primary"
      assert group =~ "text-secondary"
      # A part of zero is left out.
      refute group =~ "text-error"
      assert length(Regex.scan(~r/<rect/, group)) == 2
      [title] = Regex.run(~r/<title>(.*?)<\/title>/s, group, capture: :all_but_first)
      assert title =~ "Ada"
      assert title =~ "Bot"
      assert Enum.all?(numeric_attrs(html), &match?({_, ""}, Float.parse(&1)))
    end

    test "the parts share the bar's height in proportion, bottom first" do
      assigns = %{
        data: [
          %{
            label: "Mon",
            parts: [%{label: "a", value: 3, class: "a"}, %{label: "b", value: 1, class: "b"}]
          }
        ]
      }

      html = render(~H|<.bar_chart id="b" data={@data} />|)

      [{ya, ha}, {yb, hb}] =
        ~r/<rect x="[^"]*" y="([^"]*)" width="[^"]*" height="([^"]*)" fill="currentColor" class="(a|b)"/
        |> Regex.scan(html, capture: :all_but_first)
        |> Enum.map(fn [y, h, _] -> {String.to_float(y), String.to_float(h)} end)

      assert_in_delta ha, 3 * hb, 0.2
      # "a" is drawn first, at the bottom: below "b".
      assert ya > yb
    end

    test "y_max sets the top of the scale, but never cuts a taller bar" do
      assigns = %{data: [%{label: "Mon", value: 50}]}
      half = render(~H|<.bar_chart id="b" data={@data} y_max={100} />|)
      full = render(~H|<.bar_chart id="b" data={@data} />|)
      low = render(~H|<.bar_chart id="b" data={@data} y_max={10} />|)

      height = fn html ->
        [h] =
          Regex.run(~r/<rect[^>]*height="([^"]*)"[^>]*fill-opacity/, html,
            capture: :all_but_first
          )

        String.to_float(h)
      end

      assert_in_delta height.(half) * 2, height.(full), 0.5
      assert height.(low) == height.(full)
    end
  end
end
