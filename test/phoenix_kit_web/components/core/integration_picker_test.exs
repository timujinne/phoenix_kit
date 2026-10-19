defmodule PhoenixKitWeb.Components.Core.IntegrationPickerTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import Phoenix.Component, only: [sigil_H: 2]
  import PhoenixKitWeb.Components.Core.IntegrationPicker

  # Connection fixture shaped like what `Integrations.list_connections/1`
  # returns post-V114: `%{uuid, name, data, date_added}` with provider
  # in JSONB.
  defp conn_fixture(attrs) do
    attrs = Map.new(attrs)

    %{
      uuid: Map.get(attrs, :uuid, "019b669c-3c9d-7256-8ed1-edbc6ae29701"),
      name: Map.get(attrs, :name, "primary"),
      data:
        Map.merge(
          %{
            "provider" => Map.get(attrs, :provider, "openrouter"),
            "name" => Map.get(attrs, :name, "primary"),
            "status" => "connected"
          },
          Map.get(attrs, :data, %{})
        ),
      date_added: Map.get(attrs, :date_added, DateTime.utc_now())
    }
  end

  # ===========================================================================
  # Selection check (always rendered, ghosted when unselected)
  # ===========================================================================

  describe "selection checkmark" do
    test "renders in primary color when card is selected" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-000000000001")

      assigns = %{conns: [conn], selected: ["01900000-0000-7000-8000-000000000001"]}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="picker"
          connections={@conns}
          selected={@selected}
          on_select="select"
        />
        """)

      assert html =~ "hero-check-circle-solid"
      assert html =~ "text-primary"
    end

    test "renders ghosted (text-base-content/20) when card is unselected" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-000000000002")

      assigns = %{conns: [conn], selected: []}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="picker" connections={@conns} selected={@selected} on_select="x" />
        """)

      # Always renders the icon so the row layout doesn't shift on
      # pick/unpick — ghosted via a low-contrast colour.
      assert html =~ "hero-check-circle-solid"
      assert html =~ "text-base-content/20"
      refute html =~ "text-primary"
    end
  end

  # ===========================================================================
  # Subtitle priority: external_account_id → masked credential → empty
  # ===========================================================================

  describe "card subtitle" do
    test "shows external_account_id when present (OAuth path)" do
      conn = conn_fixture(data: %{"external_account_id" => "user@gmail.com"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "user@gmail.com"
    end

    test "shows masked api_key tail when no external_account_id" do
      conn = conn_fixture(data: %{"api_key" => "sk-or-v1-very-long-key-1234abcd"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      # only the last 4 characters
      assert html =~ "••••abcd"
      refute html =~ "sk-or-v1"
    end

    test "masks short credentials as `•••` (under 14 chars)" do
      conn = conn_fixture(data: %{"api_key" => "short-key"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "•••"
      # Short mask, not the 4-character tail one used for long keys.
      refute html =~ "••••"
      # Doesn't leak the actual short value.
      refute html =~ "short-key"
    end

    test "masks bot_token like an api_key when present" do
      conn = conn_fixture(data: %{"bot_token" => "1234567890:ABC-DEF1234-ghIjKlMn"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      # only the last 4 characters
      assert html =~ "••••KlMn"
      refute html =~ "12345678"
    end

    test "masks access_key like an api_key when present" do
      conn = conn_fixture(data: %{"access_key" => "AKIA1234567890ABCDEFG"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "••••DEFG"
      refute html =~ "AKIA1234"
    end

    test "external_account_id wins over a masked credential" do
      conn =
        conn_fixture(
          data: %{
            "external_account_id" => "user@example.com",
            "api_key" => "sk-or-v1-fall-back-ignored"
          }
        )

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "user@example.com"
      # api_key tail is NOT rendered as the subtitle.
      refute html =~ "••••ored"
    end

    test "renders no subtitle when neither account nor credential exists" do
      conn = conn_fixture(data: %{"status" => "disconnected"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      # Empty subtitle paragraph isn't rendered — `:if=...` guards it.
      refute html =~ ~r/<p[^>]*class="text-xs text-base-content\/60 truncate"/
    end
  end

  # ===========================================================================
  # Age line (uses time_ago hook)
  # ===========================================================================

  describe "age line" do
    test "renders a <time> element when date_added is set" do
      conn = conn_fixture(date_added: ~U[2026-05-01 12:00:00Z])

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Created"
      assert html =~ ~s(phx-hook="TimeAgo")
      # ISO timestamp passed through as the `datetime` attribute.
      assert html =~ "2026-05-01"
    end

    test "omits the age line when date_added is nil" do
      conn = conn_fixture(date_added: nil)

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      refute html =~ "Created"
      refute html =~ ~s(phx-hook="TimeAgo")
    end
  end

  # ===========================================================================
  # Provider def auto-resolution (icon + badge) via Providers.get/1
  # ===========================================================================

  describe "provider def auto-resolution" do
    test "renders provider icon + display name in mixed-provider mode (no `provider` attr)" do
      conn = conn_fixture(provider: "openrouter")

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      # OpenRouter is registered in PhoenixKit.Integrations.Providers
      # with both an icon and a display name. With no `provider` attr,
      # the picker is rendering a mixed list, so the per-card provider
      # badge IS useful for disambiguation.
      assert html =~ "OpenRouter"
    end

    test "hides provider badge when picker is filtered to a single provider" do
      # When `provider="openrouter"` is set, every visible card is the
      # same provider — the badge is redundant and the boss flagged
      # it as visual noise. Confirm it's gone.
      conn = conn_fixture(provider: "openrouter")

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={@conns}
          provider="openrouter"
          on_select="x"
        />
        """)

      # The provider-name badge wrapper isn't rendered. (The provider
      # icon still is — it's the visual anchor for the card.)
      refute html =~ ~s(<span class="badge badge-ghost badge-xs shrink-0">)
      # But the icon resolution still kicks in (registered provider).
      assert html =~ "hero-sparkles"
    end

    test "omits icon + badge when provider isn't in the Providers registry" do
      conn = conn_fixture(provider: "fictional-provider-xyz")

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      # No registered provider def → no provider badge (the
      # `<.icon>` block and provider-name `<span class="badge ...">`
      # are both `:if`-gated on `@provider_def`). The bare provider
      # string still appears in the card's `data-search-text` attr
      # (that's fine — search needs to find by raw key too), so we
      # assert on the rendered badge wrapper specifically.
      refute html =~ ~s(<span class="badge badge-ghost badge-xs shrink-0">)
    end
  end

  # ===========================================================================
  # Status badge
  # ===========================================================================

  describe "status badge" do
    test "Connected badge (green) for status='connected'" do
      conn = conn_fixture(data: %{"status" => "connected"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Connected"
      assert html =~ "badge-success"
    end

    test "Auth-failed badge (red) for status='error' — distinguishable from never-tested" do
      conn =
        conn_fixture(
          data: %{"status" => "error", "validation_status" => "error: Invalid credentials"}
        )

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Auth failed"
      assert html =~ "badge-error"
      # The validation message hovers as a title attribute so the
      # operator can see WHY without leaving the form.
      assert html =~ ~s(title="error: Invalid credentials")
    end

    test "Not-tested badge (yellow) for status='configured'" do
      conn = conn_fixture(data: %{"status" => "configured"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Not tested"
      assert html =~ "badge-warning"
    end

    test "Not-connected badge (grey) for status='disconnected'" do
      conn = conn_fixture(data: %{"status" => "disconnected"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Not connected"
      assert html =~ "badge-ghost"
    end

    test "Not-connected fallback for unknown / nil status" do
      conn = conn_fixture(data: %{"status" => "wat"})

      assigns = %{conns: [conn]}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "Not connected"
      assert html =~ "badge-ghost"
    end
  end

  # ===========================================================================
  # Filter by provider
  # ===========================================================================

  describe "filter by provider" do
    test "renders only connections whose JSONB provider matches" do
      conns = [
        conn_fixture(
          uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa",
          name: "OR-1",
          provider: "openrouter"
        ),
        conn_fixture(
          uuid: "01900000-0000-7000-8000-bbbbbbbbbbbb",
          name: "G-1",
          provider: "google"
        )
      ]

      assigns = %{conns: conns}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={@conns}
          provider="openrouter"
          on_select="x"
        />
        """)

      assert html =~ "OR-1"
      refute html =~ "G-1"
    end

    test "with no provider attr, renders all connections" do
      conns = [
        conn_fixture(
          uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa",
          name: "OR-1",
          provider: "openrouter"
        ),
        conn_fixture(
          uuid: "01900000-0000-7000-8000-bbbbbbbbbbbb",
          name: "G-1",
          provider: "google"
        )
      ]

      assigns = %{conns: conns}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ "OR-1"
      assert html =~ "G-1"
    end
  end

  # ===========================================================================
  # Search input visibility
  # ===========================================================================

  describe "search input" do
    test "is hidden by default when ≤ 6 connections" do
      conns =
        Enum.map(1..6, fn i ->
          conn_fixture(
            uuid: "01900000-0000-7000-8000-#{String.pad_leading("#{i}", 12, "0")}",
            name: "c-#{i}"
          )
        end)

      assigns = %{conns: conns}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      refute html =~ ~s(phx-hook="IntegrationPickerSearch")
    end

    test "auto-shows when > 6 connections" do
      conns =
        Enum.map(1..7, fn i ->
          conn_fixture(
            uuid: "01900000-0000-7000-8000-#{String.pad_leading("#{i}", 12, "0")}",
            name: "c-#{i}"
          )
        end)

      assigns = %{conns: conns}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={@conns} on_select="x" />
        """)

      assert html =~ ~s(phx-hook="IntegrationPickerSearch")
    end

    test "respects explicit `searchable: false` even past the auto-show threshold" do
      conns =
        Enum.map(1..10, fn i ->
          conn_fixture(
            uuid: "01900000-0000-7000-8000-#{String.pad_leading("#{i}", 12, "0")}",
            name: "c-#{i}"
          )
        end)

      assigns = %{conns: conns}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={@conns}
          searchable={false}
          on_select="x"
        />
        """)

      refute html =~ ~s(phx-hook="IntegrationPickerSearch")
    end
  end

  # ===========================================================================
  # Empty state
  # ===========================================================================

  describe "empty state" do
    test "shows 'No integrations configured.' when no connections" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <.integration_picker id="p" connections={[]} on_select="x" />
        """)

      assert html =~ "No integrations configured."
    end

    test "renders empty_url link when provided" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[]}
          on_select="x"
          empty_url="/admin/settings/integrations/new"
        />
        """)

      assert html =~ "/admin/settings/integrations/new"
      assert html =~ "Settings"
    end

    test "with active search, shows 'No integrations match your search.'" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[]}
          search="anything"
          on_select="x"
        />
        """)

      assert html =~ "No integrations match your search."
    end
  end

  # ===========================================================================
  # Deleted-integration card (selected uuid no longer in connections)
  # ===========================================================================

  describe "deleted-integration card" do
    test "renders warning card when selected uuid is not in connections" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[]}
          selected={["01900000-0000-7000-8000-aaaaaaaaaaaa"]}
          on_select="x"
        />
        """)

      assert html =~ "Integration deleted"
      assert html =~ "Missing"
    end

    test "doesn't render the deleted card when the selected uuid resolves" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa")

      assigns = %{conn: conn}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[@conn]}
          selected={["01900000-0000-7000-8000-aaaaaaaaaaaa"]}
          on_select="x"
        />
        """)

      refute html =~ "Integration deleted"
    end
  end

  # ===========================================================================
  # Click actions (single vs multi select)
  # ===========================================================================

  describe "click actions" do
    test "single-mode unselected card emits action='select'" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa")

      assigns = %{conn: conn}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[@conn]}
          selected={[]}
          on_select="x"
        />
        """)

      assert html =~ ~s(phx-value-action="select")
    end

    test "single-mode selected card emits action='deselect' so user can clear" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa")

      assigns = %{conn: conn}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[@conn]}
          selected={["01900000-0000-7000-8000-aaaaaaaaaaaa"]}
          on_select="x"
        />
        """)

      assert html =~ ~s(phx-value-action="deselect")
    end

    test "multi-mode unselected card emits action='add'" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa")

      assigns = %{conn: conn}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[@conn]}
          selected={[]}
          multiple={true}
          on_select="x"
        />
        """)

      assert html =~ ~s(phx-value-action="add")
    end

    test "multi-mode selected card emits action='remove'" do
      conn = conn_fixture(uuid: "01900000-0000-7000-8000-aaaaaaaaaaaa")

      assigns = %{conn: conn}

      html =
        rendered_to_string(~H"""
        <.integration_picker
          id="p"
          connections={[@conn]}
          selected={["01900000-0000-7000-8000-aaaaaaaaaaaa"]}
          multiple={true}
          on_select="x"
        />
        """)

      assert html =~ ~s(phx-value-action="remove")
    end
  end
end
