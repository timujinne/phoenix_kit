defmodule PhoenixKitWeb.Components.Core.DateInputTest do
  # async: false — one test flips the `native_date_inputs` env.
  use ExUnit.Case, async: false

  import Phoenix.Component, only: [sigil_H: 2, to_form: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.DateInput
  import PhoenixKitWeb.Components.Core.Input, only: [input: 1]

  @today ~D[2026-10-16]

  defp render(template), do: rendered_to_string(template)

  # The opening tag of the element carrying `attr`.
  defp tag(html, attr) do
    [tag] = Regex.run(~r/<(?:input|button|div)\b[^>]*\b#{attr}\b[^>]*>/s, html)
    tag
  end

  defp classes(tag) do
    [class] = Regex.run(~r/\bclass="([^"]*)"/, tag, capture: :all_but_first)
    String.split(class)
  end

  # What a browser would submit for the form around `html`: every named,
  # non-disabled control with its value.
  defp submitted(html) do
    html
    |> LazyHTML.from_fragment()
    |> LazyHTML.query("input[name], select[name], textarea[name]")
    |> Enum.reject(&(LazyHTML.attribute(&1, "disabled") != []))
    |> Map.new(fn node ->
      {hd(LazyHTML.attribute(node, "name")), List.first(LazyHTML.attribute(node, "value")) || ""}
    end)
  end

  defp text_tag(html), do: tag(html, "data-date-text")
  defp value_tag(html), do: tag(html, "data-date-value")

  defp date(extra \\ []) do
    assigns = %{
      extra:
        Keyword.merge(
          [
            id: "due",
            name: "order[due]",
            value: ~D[2026-01-05],
            format: "d.m.Y",
            locale: "et",
            week_start: 1,
            today: @today
          ],
          extra
        )
    }

    render(~H"""
    <.date_input {@extra} />
    """)
  end

  describe "visible text in the site format" do
    for {format, text} <- [
          {"Y-m-d", "2026-01-05"},
          {"m/d/Y", "01/05/2026"},
          {"d/m/Y", "05/01/2026"},
          {"d.m.Y", "05.01.2026"},
          {"d-m-Y", "05-01-2026"},
          {"F j, Y", "January 5, 2026"}
        ] do
      test "format #{format}" do
        html = date(format: unquote(format))
        assert text_tag(html) =~ ~s(value="#{unquote(text)}")
        assert html =~ ~s(data-format="#{unquote(format)}")
        # The value element keeps the ISO value whatever the format is.
        assert value_tag(html) =~ ~s(value="2026-01-05")
      end
    end

    test "an unknown format falls back to Y-m-d, as format_date/2 does" do
      assert text_tag(date(format: "d.m")) =~ ~s(value="2026-01-05")
      assert date(format: "d.m") =~ ~s(data-format="Y-m-d")
    end

    test "the default format and today need no database" do
      assigns = %{}

      html =
        render(~H"""
        <.date_input id="x" name="x" value={~D[2026-01-05]} />
        """)

      assert text_tag(html) =~ ~s(value="2026-01-05")
      assert html =~ ~r/data-today="\d{4}-\d{2}-\d{2}"/
    end

    test "the placeholder is the format pattern, not a date" do
      assert text_tag(date()) =~ ~s(placeholder="dd.mm.yyyy")
      assert text_tag(date(format: "m/d/Y")) =~ ~s(placeholder="mm/dd/yyyy")
      assert text_tag(date(placeholder: "pick")) =~ ~s(placeholder="pick")
    end

    test "text mode: a textual format gets the text keyboard" do
      assert text_tag(date()) =~ ~s(inputmode="numeric")
      assert text_tag(date(format: "F j, Y")) =~ ~s(inputmode="text")
    end

    test "a DateTime and a NaiveDateTime are shown as dates" do
      assert text_tag(date(value: ~U[2026-01-05 10:00:00Z])) =~ ~s(value="05.01.2026")
      assert value_tag(date(value: ~N[2026-01-05 10:00:00])) =~ ~s(value="2026-01-05")
    end

    test "an ISO string is understood; anything else is echoed unchanged" do
      html = date(value: "2026-01-05")
      assert text_tag(html) =~ ~s(value="05.01.2026")

      html = date(value: "5.1.26")
      assert text_tag(html) =~ ~s(value="5.1.26")
      assert value_tag(html) =~ ~s(value="5.1.26")
    end

    test "nil and empty are empty in both elements" do
      for v <- [nil, ""] do
        html = date(value: v)
        assert text_tag(html) =~ ~s(value="")
        assert value_tag(html) =~ ~s(value="")
      end
    end
  end

  describe "markup" do
    test "the visible input has the caller's id and no name; the value element has the name" do
      html = date()
      text = text_tag(html)
      value = value_tag(html)

      assert text =~ ~s(id="due")
      assert text =~ ~s(type="text")
      refute text =~ ~s(name=)
      assert value =~ ~s(type="date")
      assert value =~ ~s(id="due-value")
      assert value =~ ~s(name="order[due]")
      # Once the hook sets `data-enhanced` it is rendered but invisible, not
      # hidden / display:none (LiveViewTest and showPicker() need it live).
      assert "group-data-[enhanced]/pk-date:opacity-0" in classes(value)
      assert "group-data-[enhanced]/pk-date:pointer-events-none" in classes(value)
      refute value =~ ~s(type="hidden")
      refute value =~ "display:none"
    end

    test "the wrapper is the group the enhanced classes key on" do
      assert "group/pk-date" in classes(tag(date(), "phx-hook"))
    end

    test "an atom id builds the derived ids too" do
      html = date(id: :due)
      assert html =~ ~s(id="due-wrap")
      assert html =~ ~s(id="due-value")
      assert html =~ ~s(aria-describedby="due-hint")
    end

    test "the wrapper carries the hook and the server data" do
      html = date(min: ~D[2026-01-01], max: "2026-12-31", week_start: 7, locale: "de_AT")
      wrap = tag(html, "phx-hook")

      assert wrap =~ ~s(id="due-wrap")
      assert wrap =~ ~s(phx-hook="PkDateInput")
      assert wrap =~ ~s(data-min="2026-01-01")
      assert wrap =~ ~s(data-max="2026-12-31")
      assert wrap =~ ~s(data-today="2026-10-16")
      # ISO Sunday (7) is Cally's 0; `_` becomes `-`.
      assert wrap =~ ~s(data-week-start="0")
      assert wrap =~ ~s(data-locale="de-AT")
      assert wrap =~ ~s(data-expected="Expected 16.10.2026")
      assert value_tag(html) =~ ~s(min="2026-01-01")
      assert value_tag(html) =~ ~s(max="2026-12-31")
    end

    test "week_start accepts the Settings string and falls back to Monday" do
      assert tag(date(week_start: "3"), "phx-hook") =~ ~s(data-week-start="3")
      assert tag(date(week_start: "junk"), "phx-hook") =~ ~s(data-week-start="1")
    end

    test "a malformed locale falls back to en" do
      assert tag(date(locale: "not a tag!"), "phx-hook") =~ ~s(data-locale="en")
    end

    test "the id is derived from the name when none is given" do
      assigns = %{}

      html =
        render(~H"""
        <.date_input
          name="value[from]"
          value={nil}
          format="d.m.Y"
          locale="en"
          week_start={1}
          today={~D[2026-10-16]}
        />
        """)

      assert html =~ ~s(id="value-from")
      assert html =~ ~s(id="value-from-wrap")
      assert html =~ ~s(id="value-from-value")
    end

    test "size sets the daisyUI modifier" do
      assert text_tag(date(size: "xs")) =~ "input-xs"
      assert text_tag(date(size: "sm")) =~ "input-sm"
      refute text_tag(date()) =~ "input-xs"
    end

    test "a label is tied to the visible input and shows the required marker" do
      html = date(label: "Due", required: true)
      assert html =~ ~s(for="due")
      assert html =~ "Due"
      assert html =~ ~s(text-error)
    end
  end

  describe "the clear button" do
    defp clear_tag(html), do: Regex.run(~r/<button[^>]*data-clear[^>]*>/s, html)

    test "shown for a filled optional field" do
      [tag] = clear_tag(date())
      refute tag =~ "hidden"
      assert tag =~ ~s(tabindex="-1")
      assert tag =~ ~s(aria-label="Clear date")
    end

    test "its name and the calendar button's include the field's label" do
      html = date(label: "Due")
      assert tag(html, "data-clear") =~ ~s(aria-label="Clear date for Due")
      assert tag(html, "data-open") =~ ~s(aria-label="Open calendar for Due")

      html = date(bare: true, "aria-label": "From")
      assert tag(html, "data-clear") =~ ~s(aria-label="Clear date for From")
      assert tag(html, "data-open") =~ ~s(aria-label="Open calendar for From")
    end

    test "rendered but hidden while the field is empty" do
      [tag] = clear_tag(date(value: nil))
      assert tag =~ "hidden"
    end

    test "not rendered when required, disabled or readonly" do
      assert clear_tag(date(required: true)) == nil
      assert clear_tag(date(disabled: true)) == nil
      assert clear_tag(date(readonly: true)) == nil
    end

    test "the calendar button is a tab stop" do
      assert tag(date(), "data-open") =~ ~s(tabindex="0")
      assert tag(date(), "data-open") =~ ~s(aria-label="Open calendar")
    end
  end

  describe "accessibility and routing details" do
    test "the calendar button names its popup; the popup is a labelled dialog" do
      html = date(label: "Due")
      button = tag(html, "data-open")
      assert button =~ ~s(aria-haspopup="dialog")
      assert button =~ ~s(aria-expanded="false")
      assert button =~ ~s(aria-controls="due-popup")
      [popup] = Regex.run(~r/<div[^>]*id="due-popup"[^>]*>/s, html)
      assert popup =~ ~s(role="dialog")
      assert popup =~ ~s(aria-label="Due")
    end

    test "style, title and focus/key handlers go to the visible input" do
      html = date(style: "width: 9rem", title: "T", onfocus: "f()", onkeyup: "k()")

      for attr <- [~s(style="width: 9rem"), ~s(title="T"), "onfocus=\"f()\"", "onkeyup=\"k()\""] do
        assert text_tag(html) =~ attr
        refute value_tag(html) =~ attr
      end
    end

    test "the button padding follows what is on the right" do
      assert text_tag(date()) =~ "pr-14"
      assert text_tag(date(required: true)) =~ "pr-9"
      assert text_tag(date(size: "xs", required: true)) =~ "pr-7"
    end

    test "html: a map of attributes behaves like rest" do
      html = date(html: %{"phx-change": "c", "phx-blur": "b", "phx-debounce": "9"})
      assert value_tag(html) =~ ~s(phx-change="c")
      assert text_tag(html) =~ ~s(phx-blur="b")
      refute html =~ "phx-debounce"
    end
  end

  describe "range, form and popup details" do
    test "min/max give a message for a date outside the range, in the site format" do
      wrap = fn extra -> tag(date(extra), "phx-hook") end

      assert wrap.(min: ~D[2026-10-01], max: ~D[2026-10-31]) =~
               ~s(data-range-message="Pick a date between 01.10.2026 and 31.10.2026")

      assert wrap.(min: ~D[2026-10-01]) =~
               ~s(data-range-message="Pick a date on or after 01.10.2026")

      assert wrap.(max: "2026-10-31") =~
               ~s(data-range-message="Pick a date on or before 31.10.2026")

      refute wrap.([]) =~ "data-range-message"
    end

    test "the footer buttons carry no state: LiveView does not patch a <template>" do
      # "Today" being off (today outside min/max) is decided by the hook from
      # the wrapper's data-* each time the calendar opens, so the template is
      # the same whatever the range is.
      template = fn extra ->
        [t] = Regex.run(~r/<template.*?<\/template>/s, date(extra))
        t
      end

      assert template.(min: ~D[2026-10-17]) == template.([])
      assert template.(max: ~D[2026-10-15]) == template.([])
      refute template.([]) =~ "disabled"

      html = date(min: ~D[2026-10-17])
      assert tag(html, "phx-hook") =~ ~s(data-min="2026-10-17")
      assert tag(html, "phx-hook") =~ ~s(data-today="2026-10-16")
    end

    test "form= goes to both inputs, so Enter in the text submits that form" do
      html = date(form: "other-form")
      assert text_tag(html) =~ ~s(form="other-form")
      assert value_tag(html) =~ ~s(form="other-form")
    end

    test "native honours the html map" do
      html = date(native: true, html: %{"phx-change": "c", "data-x": "y"})
      assert html =~ ~s(phx-change="c")
      assert html =~ ~s(data-x="y")
    end

    test "the popup is labelled Calendar when the field has no label" do
      [popup] = Regex.run(~r/<div[^>]*id="due-popup"[^>]*>/s, date())
      assert popup =~ ~s(aria-label="Calendar")
    end
  end

  describe "calendar popup" do
    test "a template carries the calendar and the server's strings" do
      html = date()

      assert html =~ "data-popup-template"
      assert html =~ ~r/<calendar-date[^>]*class="cally"/
      assert html =~ ~s(slot="previous")
      assert html =~ ~s(slot="next")
      assert html =~ "<calendar-month>"
      assert html =~ "Previous month"
      assert html =~ "Next month"
      assert html =~ ~r/<button[^>]*data-popup-today[^>]*>\s*Today/
      assert html =~ ~r/<button[^>]*data-popup-clear[^>]*>\s*Clear/
    end

    test "the popup container is a manual popover LiveView leaves alone" do
      html = date()
      [popup] = Regex.run(~r/<div[^>]*id="due-popup"[^>]*>/s, html)

      assert popup =~ ~s(id="due-popup")
      assert popup =~ ~s(popover="manual")
      assert popup =~ ~s(phx-update="ignore")
      # The UA centres a popover with `inset: 0; margin: auto`: undone for positioning.
      assert popup =~ "inset-auto"
      assert popup =~ "m-0"
    end

    test "footer Clear follows the ✕ rules, through the wrapper's data-clearable" do
      assert tag(date(), "phx-hook") =~ ~s(data-clearable="true")

      for extra <- [[required: true], [disabled: true], [readonly: true]] do
        refute tag(date(extra), "phx-hook") =~ "data-clearable"
      end

      assert date(required: true) =~ "data-popup-today"
    end

    test "disabled and readonly fields have no popup" do
      for extra <- [[disabled: true], [readonly: true]] do
        html = date(extra)
        refute html =~ "-popup"
        refute html =~ "calendar-date"
      end
    end

    test "native has no popup or hook" do
      refute date(native: true) =~ "calendar-date"
    end
  end

  describe "attribute routing" do
    test "required sits on the date input until the hook moves it; readonly on both" do
      html = date(required: true, readonly: true)
      # A `required` text field that is `hidden` would block the form's submit
      # on a page where the hook never runs.
      refute text_tag(html) =~ "required"
      assert value_tag(html) =~ "required"
      assert tag(html, "phx-hook") =~ ~s(data-required="true")
      assert text_tag(html) =~ "readonly"
      assert value_tag(html) =~ "readonly"

      refute tag(date(), "phx-hook") =~ "data-required"
      refute value_tag(date()) =~ "required"
    end

    test "disabled goes to both" do
      html = date(disabled: true)
      assert text_tag(html) =~ "disabled"
      assert value_tag(html) =~ "disabled"
      refute html =~ "data-open"
    end

    test "phx-debounce is dropped, focus and key bindings go to the visible input" do
      html =
        date(
          "phx-debounce": "blur",
          "phx-blur": "b",
          "phx-keydown": "k",
          onkeydown: "x()",
          "aria-label": "Deadline",
          "phx-change": "chg",
          form: "f1",
          "data-x": "y"
        )

      refute html =~ "phx-debounce"
      text = text_tag(html)
      value = value_tag(html)

      for attr <- [~s(phx-blur="b"), ~s(phx-keydown="k"), "onkeydown=\"x()\""] do
        assert text =~ attr
        refute value =~ attr
      end

      # The visible input is the named one for assistive tech; the date input
      # carries the same name only so that it has one before the hook runs.
      assert text =~ ~s(aria-label="Deadline")
      assert value =~ ~s(aria-label="Deadline")

      assert text =~ ~s(form="f1")

      for attr <- [~s(phx-change="chg"), ~s(form="f1"), ~s(data-x="y")] do
        assert value =~ attr
        if attr != ~s(form="f1"), do: refute(text =~ attr)
      end
    end
  end

  describe "attribute routing: what lands on which element" do
    test "tabindex, language, click and the like go to the visible input" do
      html =
        date(
          tabindex: "3",
          spellcheck: "false",
          lang: "de",
          "phx-click": "go",
          "phx-target": "#t"
        )

      text = text_tag(html)
      value = value_tag(html)

      for attr <- [~s(tabindex="3"), ~s(spellcheck="false"), ~s(lang="de"), ~s(phx-click="go")] do
        assert text =~ attr, attr
        refute value =~ attr, attr
      end

      # One tabindex each: the caller's, on the element a person can focus.
      assert length(Regex.scan(~r/tabindex=/, text)) == 1
      refute value =~ "tabindex"

      # LiveView reads phx-target from the element that fires the event, and
      # phx-click fires on the visible one: both carry it.
      assert value =~ ~s(phx-target="#t")
      assert text =~ ~s(phx-target="#t")
    end

    test "form, step, list, phx-change and data-* go to the value element" do
      html = date(step: "7", list: "days", "data-x": "y", "phx-change": "c")
      value = value_tag(html)

      for attr <- [~s(step="7"), ~s(list="days"), ~s(data-x="y"), ~s(phx-change="c")] do
        assert value =~ attr, attr
        refute text_tag(html) =~ attr, attr
      end
    end

    test "phx-value-* goes to both elements: click and blur events read it from the visible one" do
      html = date("phx-value-id": "9", "phx-blur": "save")
      assert text_tag(html) =~ ~s(phx-value-id="9")
      assert value_tag(html) =~ ~s(phx-value-id="9")
    end

    test "autocomplete is accepted without a compile warning" do
      warnings =
        ExUnit.CaptureIO.capture_io(:stderr, fn ->
          Code.compile_string("""
          defmodule DateInputAutocompleteProbe do
            use Phoenix.Component
            import PhoenixKitWeb.Components.Core.DateInput

            def render(assigns) do
              ~H'<.date_input id="a" name="a" autocomplete="bday" />'
            end
          end
          """)
        end)

      refute warnings =~ "undefined attribute"
    end

    test "attributes that mean nothing for a date are dropped, not sent to the text field" do
      html = date(pattern: "[0-9]+", maxlength: "4", minlength: "2", size: "9", multiple: true)

      for attr <- ["pattern", "maxlength", "minlength", ~s(size=), "multiple"] do
        refute html =~ attr, attr
      end
    end

    test "the caller's aria-describedby is kept and the rejection hint added" do
      assert text_tag(date()) =~ ~s(aria-describedby="due-hint")
      assert text_tag(date("aria-describedby": "help")) =~ ~s(aria-describedby="help due-hint")
    end

    test "the rejection hint is a live region LiveView leaves alone" do
      [hint] = Regex.run(~r/<span[^>]*data-date-hint[^>]*>/s, date())
      assert hint =~ ~s(id="due-hint")
      assert hint =~ ~s(role="status")
      assert hint =~ ~s(phx-update="ignore")
    end
  end

  describe "without LiveView (a controller template, no hook)" do
    # The server markup alone: no hook has run, so what is displayed and what
    # is submitted must already be the date input.
    test "the only control that submits is a displayed date input with the ISO value" do
      html = date()
      assert submitted(html) == %{"order[due]" => "2026-01-05"}

      value = value_tag(html)
      assert value =~ ~s(type="date")
      assert value =~ ~s(value="2026-01-05")
      refute "hidden" in classes(value)
      refute "opacity-0" in classes(value)
      refute value =~ ~s(aria-hidden)
      refute value =~ "tabindex"

      # The text field and the buttons are hidden until the wrapper is enhanced.
      assert "hidden" in classes(text_tag(html))
      refute text_tag(html) =~ "name="
    end

    test "a required field submits and validates through the date input" do
      html = date(required: true)
      assert submitted(html) == %{"order[due]" => "2026-01-05"}
      refute text_tag(html) =~ "required"
      assert value_tag(html) =~ "required"
    end

    test "a date chosen in that control arrives in the controller's params" do
      html = date()

      # The browser puts the chosen date in the one displayed, named control and
      # posts it: nothing else in the markup competes for the `order[due]` key.
      body = URI.encode_query(%{"order[due]" => "2026-02-03"})

      conn =
        :post
        |> Plug.Test.conn("/save", body)
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))

      assert conn.params == %{"order" => %{"due" => "2026-02-03"}}
      assert Map.keys(submitted(html)) == ["order[due]"]
    end

    test "an empty or non-date value submits as the date input would" do
      assert submitted(date(value: nil)) == %{"order[due]" => ""}
      assert submitted(date(value: "")) == %{"order[due]" => ""}
    end

    test "a disabled field submits nothing" do
      assert submitted(date(disabled: true)) == %{}
    end

    test "<.input type=\"date\"> in a plain form" do
      assigns = %{}

      html =
        render(~H"""
        <form action="/save" method="post">
          <.input type="date" id="d1" name="row[d]" value={~D[2026-01-05]} required />
        </form>
        """)

      assert submitted(html) == %{"row[d]" => "2026-01-05"}
      refute html =~ ~s(name="row[d]" value="05)
    end

    test "the enhanced classes live on the wrapper's data attribute, so nothing hides before it" do
      html = date()
      assert "group-data-[enhanced]/pk-date:inline-flex" in classes(text_tag(html))
      refute tag(html, "phx-hook") =~ "data-enhanced"
    end
  end

  describe "errors" do
    test "FormField errors mark the input and render under it" do
      changeset =
        {%{}, %{due: :date}}
        |> Ecto.Changeset.cast(%{"due" => "2026-01-05"}, [:due])
        |> Ecto.Changeset.add_error(:due, "is bad")
        |> Map.put(:action, :validate)

      assigns = %{form: to_form(changeset, as: "order")}

      html =
        render(~H"""
        <.date_input field={@form[:due]} format="d.m.Y" locale="en" week_start={1} today={~D[2026-10-16]} />
        """)

      text = text_tag(html)
      assert text =~ ~s(id="order_due")
      assert text =~ "input-error"
      assert text =~ ~s(aria-invalid="true")
      assert text =~ "data-has-errors"
      assert text =~ ~s(value="05.01.2026")
      assert value_tag(html) =~ ~s(name="order[due]")
      assert html =~ "is bad"
    end

    test "no errors, no marks" do
      text = text_tag(date())
      refute text =~ "input-error"
      refute text =~ "aria-invalid"
    end
  end

  describe "bare" do
    test "no label, outer wrapper or error list; the label becomes aria-label" do
      html = date(bare: true, label: "From", errors: ["x"])
      refute html =~ "phx-feedback-for"
      refute html =~ "<label"
      refute html =~ ">x<"
      assert text_tag(html) =~ ~s(aria-label="From")
      assert text_tag(html) =~ "input-error"
      refute text_tag(html) =~ "w-full"
      assert html =~ "inline-block"
    end

    test "an explicit aria-label wins" do
      assert text_tag(date(bare: true, label: "From", "aria-label": "Own")) =~
               ~s(aria-label="Own")
    end
  end

  describe "native" do
    test "renders today's plain date input" do
      html = date(native: true, "phx-debounce": "300")

      assert html =~ ~s(type="date")
      assert html =~ ~s(name="order[due]")
      assert html =~ ~s(id="due")
      assert html =~ ~s(value="2026-01-05")
      assert html =~ ~s(phx-debounce="300")
      refute html =~ "phx-hook"
      refute html =~ "data-date-text"
    end
  end

  describe "<.input type=\"date\">" do
    defp input_date(extra \\ []) do
      assigns = %{
        extra:
          Keyword.merge(
            [type: "date", id: "d1", name: "row[d]", value: ~D[2026-01-05]],
            extra
          )
      }

      render(~H"""
      <.input {@extra} />
      """)
    end

    test "delegates to date_input" do
      html = input_date(label: "When", min: "2026-01-01", max: "2026-12-31", required: true)

      assert html =~ ~s(phx-hook="PkDateInput")
      assert html =~ ~s(for="d1")
      assert value_tag(html) =~ ~s(name="row[d]")
      assert value_tag(html) =~ ~s(min="2026-01-01")
      assert value_tag(html) =~ ~s(max="2026-12-31")
      assert value_tag(html) =~ "required"
      assert tag(html, "phx-hook") =~ ~s(data-required="true")
    end

    test "an :icon slot has no place in the widget: the input stays native" do
      assigns = %{}

      html =
        render(~H"""
        <.input type="date" id="d1" name="row[d]" value={~D[2026-01-05]}>
          <:icon><span class="my-icon"></span></:icon>
        </.input>
        """)

      assert html =~ "my-icon"
      assert html =~ ~s(type="date")
      refute html =~ "phx-hook"
      assert submitted(html) == %{"row[d]" => "2026-01-05"}
    end

    test "attributes meant for a native date input reach the right element" do
      html =
        input_date(step: "7", tabindex: "2", pattern: "x", maxlength: "3", autocomplete: "bday")

      assert value_tag(html) =~ ~s(step="7")
      assert text_tag(html) =~ ~s(tabindex="2")
      refute html =~ "pattern"
      refute html =~ "maxlength"
    end

    # The attributes as a browser reads them: the first of a repeated one wins.
    defp text_attrs(html) do
      html
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("[data-date-text]")
      |> Enum.at(0)
      |> LazyHTML.attributes()
      |> List.first()
      |> Enum.reverse()
      |> Map.new()
    end

    defp count_attr(tag, name), do: length(Regex.scan(~r/\s#{name}=/, tag))

    test "the visible input defaults to autocomplete=off and a numeric keyboard, once" do
      html = date()
      attrs = text_attrs(html)

      assert attrs["autocomplete"] == "off"
      assert attrs["inputmode"] == "numeric"
      assert count_attr(text_tag(html), "autocomplete") == 1
      assert count_attr(text_tag(html), "inputmode") == 1

      assert text_attrs(date(format: "F j, Y"))["inputmode"] == "text"
    end

    test "a caller's autocomplete and inputmode replace the defaults instead of repeating them" do
      html = date(autocomplete: "bday", inputmode: "decimal")
      attrs = text_attrs(html)

      assert attrs["autocomplete"] == "bday"
      assert attrs["inputmode"] == "decimal"
      assert count_attr(text_tag(html), "autocomplete") == 1
      assert count_attr(text_tag(html), "inputmode") == 1
      refute value_tag(html) =~ "autocomplete"

      via_input = input_date(autocomplete: "bday")
      assert text_attrs(via_input)["autocomplete"] == "bday"
      assert count_attr(text_tag(via_input), "autocomplete") == 1
    end

    test "autofocus is on the visible input and on the native one a dead page shows" do
      html = date(autofocus: true)
      assert Map.has_key?(text_attrs(html), "autofocus")
      assert value_tag(html) =~ "autofocus"
    end

    test "size is the HTML size there, so it is not passed on" do
      html = input_date(size: "20")
      refute html =~ ~s(size="20")
      refute text_tag(html) =~ "input-xs"
    end

    test "per-call native keeps the plain input" do
      html = input_date(native: true)
      assert html =~ ~s(<input type="date")
      refute html =~ "phx-hook"
    end

    test "the host opt-out restores the plain input everywhere" do
      Application.put_env(:phoenix_kit, :native_date_inputs, true)
      on_exit(fn -> Application.delete_env(:phoenix_kit, :native_date_inputs) end)

      html = input_date()
      assert html =~ ~s(<input type="date")
      refute html =~ "phx-hook"
    end

    test "other types are untouched" do
      assigns = %{}

      html =
        render(~H"""
        <.input type="datetime-local" id="t" name="t" value="2026-01-05T10:00" />
        """)

      assert html =~ ~s(type="datetime-local")
      refute html =~ "phx-hook"
    end

    test "a bound field delegates with its name, id and errors" do
      changeset =
        {%{}, %{due: :date}}
        |> Ecto.Changeset.cast(%{"due" => "2026-01-05"}, [:due])
        |> Ecto.Changeset.add_error(:due, "is bad")
        |> Map.put(:action, :validate)

      assigns = %{form: to_form(changeset, as: "order")}

      html =
        render(~H"""
        <.input field={@form[:due]} type="date" />
        """)

      assert text_tag(html) =~ ~s(id="order_due")
      assert value_tag(html) =~ ~s(name="order[due]")
      assert html =~ "is bad"
    end
  end
end
