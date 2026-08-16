defmodule PhoenixKitWeb.Live.Settings.OrganizationMainCountriesTest do
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.Routes

  # Sets up the organization settings the "Main countries" card reads from,
  # logs in a fresh admin, and mounts the page. Each call is self-contained
  # (its own admin + conn) so a test can mount two independent sessions to
  # exercise the PubSub broadcast between them.
  defp mount_organization(opts) do
    country = Keyword.get(opts, :country, "EE")
    main_countries = Keyword.get(opts, :main_countries, "")

    Settings.update_json_setting("company_info", %{"name" => "Acme OÜ", "country" => country})
    Settings.update_setting("country_select_priority", main_countries)

    {admin, _token} = create_admin_user()
    conn = log_in_user(build_conn(), admin)
    {:ok, lv, html} = live(conn, Routes.path("/admin/settings/organization"))
    {lv, html}
  end

  defp stored_priority, do: Settings.get_setting("country_select_priority")

  # Country names appear twice on this page — once in the always-present
  # 250-country <select>, once (maybe) in the "Based on your country"
  # suggestion — so a bare `html =~ "Finland"` proves nothing either way.
  # This pulls just the suggestion sentence's interpolated country list.
  defp suggested_countries_text(html) do
    case Regex.run(~r/Based on your country: ([^<]*)/, html) do
      [_, text] -> text
      nil -> ""
    end
  end

  # ===================================
  # FIX 1 & FIX 2 — forged payloads must never crash a handler
  # ===================================

  describe "forged payloads never crash the handlers" do
    test "add_main_country ignores a non-binary code" do
      {lv, _html} = mount_organization(main_countries: "EE")

      for bad_code <- [42, ["EE"], %{}] do
        render_hook(lv, "add_main_country", %{"code" => bad_code})
      end

      assert stored_priority() == "EE"
    end

    test "add_main_country with no code param is a no-op" do
      {lv, _html} = mount_organization(main_countries: "EE")

      render_hook(lv, "add_main_country", %{})

      assert stored_priority() == "EE"
    end

    test "reorder_main_countries ignores a non-list ordered_ids" do
      {lv, _html} = mount_organization(main_countries: "EE, FI")

      for bad_ordered <- ["SE", nil, 1, %{}] do
        render_hook(lv, "reorder_main_countries", %{"ordered_ids" => bad_ordered})
      end

      assert stored_priority() == "EE, FI"
    end

    test "reorder_main_countries with no ordered_ids param is a no-op" do
      {lv, _html} = mount_organization(main_countries: "EE, FI")

      render_hook(lv, "reorder_main_countries", %{})

      assert stored_priority() == "EE, FI"
    end

    test "remove_main_country with no code param is a no-op" do
      {lv, _html} = mount_organization(main_countries: "EE, FI")

      render_hook(lv, "remove_main_country", %{})

      assert stored_priority() == "EE, FI"
    end

    test "move_main_country ignores a malformed payload" do
      {lv, _html} = mount_organization(main_countries: "EE, FI")

      for bad_payload <- [
            %{"code" => 42, "direction" => "up"},
            %{"code" => "EE", "direction" => "sideways"},
            %{"code" => "EE"},
            %{}
          ] do
        render_hook(lv, "move_main_country", bad_payload)
      end

      assert stored_priority() == "EE, FI"
    end
  end

  # ===================================
  # reorder_main_countries — only ever reorders the pinned set
  # ===================================

  describe "reorder_main_countries only ever reorders the pinned set" do
    test "an unrecognized id in the payload is not added" do
      {lv, _html} = mount_organization(main_countries: "EE, FI, LV")

      render_hook(lv, "reorder_main_countries", %{"ordered_ids" => ["ZZ", "LV", "EE", "FI"]})

      assert stored_priority() == "LV, EE, FI"
    end

    test "an omitted id is re-appended rather than dropped" do
      {lv, _html} = mount_organization(main_countries: "EE, FI, LV")

      render_hook(lv, "reorder_main_countries", %{"ordered_ids" => ["LV"]})

      assert stored_priority() == "LV, EE, FI"
    end

    test "a duplicated id in the payload does not duplicate the stored list" do
      {lv, _html} = mount_organization(main_countries: "EE, FI, LV")

      render_hook(lv, "reorder_main_countries", %{"ordered_ids" => ["LV", "LV", "EE", "FI"]})

      assert stored_priority() == "LV, EE, FI"
    end
  end

  # ===================================
  # add_main_country — dedupe, unknown codes, empty selection (FIX 8)
  # ===================================

  describe "add_main_country" do
    test "adding a code that is already pinned changes nothing" do
      {lv, _html} = mount_organization(main_countries: "EE, FI")

      render_hook(lv, "add_main_country", %{"code" => "ee"})

      assert stored_priority() == "EE, FI"
    end

    test "adding a code that names no country is dropped" do
      {lv, _html} = mount_organization(main_countries: "EE")

      render_hook(lv, "add_main_country", %{"code" => "ZZ"})

      assert stored_priority() == "EE"
    end

    test "adding a new known code appends it" do
      {lv, _html} = mount_organization(main_countries: "EE")

      render_hook(lv, "add_main_country", %{"code" => "fi"})

      assert stored_priority() == "EE, FI"
    end

    # FIX 8: pressing "Add" with nothing selected must not rewrite the
    # (identical) setting.
    test "an empty code is a no-op" do
      {lv, _html} = mount_organization(main_countries: "EE")

      render_hook(lv, "add_main_country", %{"code" => ""})

      assert stored_priority() == "EE"
    end
  end

  # ===================================
  # FIX 5 — move_main_country: up/down, clamped at the ends
  # ===================================

  describe "move_main_country" do
    test "moves a row up and stops at the top" do
      {lv, _html} = mount_organization(main_countries: "EE, FI, LV")

      render_hook(lv, "move_main_country", %{"code" => "LV", "direction" => "up"})
      assert stored_priority() == "EE, LV, FI"

      render_hook(lv, "move_main_country", %{"code" => "EE", "direction" => "up"})
      assert stored_priority() == "EE, LV, FI"
    end

    test "moves a row down and stops at the bottom" do
      {lv, _html} = mount_organization(main_countries: "EE, FI, LV")

      render_hook(lv, "move_main_country", %{"code" => "EE", "direction" => "down"})
      assert stored_priority() == "FI, EE, LV"

      render_hook(lv, "move_main_country", %{"code" => "LV", "direction" => "down"})
      assert stored_priority() == "FI, EE, LV"
    end
  end

  describe "move_main_country buttons in the rendered card" do
    test "carry the reused Move up/Move down aria-labels and are disabled at the ends" do
      {_lv, html} = mount_organization(main_countries: "EE, FI, LV")
      doc = Floki.parse_document!(html)

      up_first = Floki.find(doc, ~s(button[phx-value-code="EE"][phx-value-direction="up"]))
      down_first = Floki.find(doc, ~s(button[phx-value-code="EE"][phx-value-direction="down"]))
      up_last = Floki.find(doc, ~s(button[phx-value-code="LV"][phx-value-direction="up"]))
      down_last = Floki.find(doc, ~s(button[phx-value-code="LV"][phx-value-direction="down"]))

      assert Floki.attribute(up_first, "aria-label") == ["Move up"]
      assert Floki.attribute(down_first, "aria-label") == ["Move down"]

      # First row: can't move up, can move down.
      assert Floki.attribute(up_first, "disabled") != []
      assert Floki.attribute(down_first, "disabled") == []

      # Last row: can move up, can't move down.
      assert Floki.attribute(up_last, "disabled") == []
      assert Floki.attribute(down_last, "disabled") != []
    end
  end

  # ===================================
  # FIX 3 — the Company card's country <select> must refresh too
  # ===================================

  test "adding a main country refreshes the Company card's country select" do
    {lv, html} = mount_organization(main_countries: "")

    {af_before, _len} = :binary.match(html, ~s(value="AF"))
    {ee_before, _len} = :binary.match(html, ~s(value="EE"))
    assert af_before < ee_before

    html = render_hook(lv, "add_main_country", %{"code" => "EE"})

    {ee_after, _len} = :binary.match(html, ~s(value="EE"))
    {af_after, _len} = :binary.match(html, ~s(value="AF"))
    assert ee_after < af_after
  end

  # ===================================
  # FIX 4 — main-country actions broadcast to other admin sessions
  # ===================================

  test "an add action broadcasts to a second admin session" do
    {lv_a, _html_a} = mount_organization(main_countries: "EE")
    {lv_b, html_b} = mount_organization(main_countries: "EE")

    # `phx-value-code="FI"` only appears on a pinned row's move/remove
    # buttons — unlike the country name, it can't also come from the
    # always-present 250-country <select> or the suggestion sentence.
    refute html_b =~ ~s(phx-value-code="FI")

    render_hook(lv_a, "add_main_country", %{"code" => "FI"})

    assert render(lv_b) =~ ~s(phx-value-code="FI")
  end

  # ===================================
  # FIX 9 — country_changed must recompute the suggestion, unsaved
  # ===================================

  test "country_changed recomputes the suggestion without persisting the country" do
    {lv, html} = mount_organization(country: "EE", main_countries: "")

    assert suggested_countries_text(html) =~ "Latvia"
    refute suggested_countries_text(html) =~ "Luxembourg"

    html = render_hook(lv, "country_changed", %{"company_country" => "DE"})

    assert suggested_countries_text(html) =~ "Luxembourg"
    refute suggested_countries_text(html) =~ "Latvia"

    # Only the in-memory suggestion moved — nothing was saved.
    assert Settings.get_json_setting("company_info")["country"] == "EE"
  end
end
