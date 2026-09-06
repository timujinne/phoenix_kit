if Code.ensure_loaded?(PhoenixKit.Install.AdminLabelConfig) do
  defmodule PhoenixKit.Install.AdminLabelConfigTest do
    @moduledoc """
    The comment block `mix phoenix_kit.install` / `.update` append to a host's
    `config/config.exs` so the admin-area naming vocabulary is in front of a
    developer at the moment they go to change it.
    """
    use ExUnit.Case, async: true

    alias PhoenixKit.Config
    alias PhoenixKit.Install.AdminLabelConfig

    describe "block/0" do
      test "is entirely comments" do
        # Load-bearing. The block is APPENDED to config/config.exs, after
        # `import_config` and whatever else the host has — which is only safe
        # because it cannot execute. One stray uncommented line would be live
        # config running last, overriding the host's own.
        offenders =
          AdminLabelConfig.block()
          |> String.split("\n")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))

        assert offenders == [], "non-comment lines in the block: #{inspect(offenders)}"
      end

      test "names every preset and the segment it pairs with" do
        # Guards the same drift `AdminLabel.preset_text/1` does, from the other
        # side: a preset added to Config without a `label_hint/1` clause here
        # would raise FunctionClauseError partway through somebody's install.
        block = AdminLabelConfig.block()

        for {preset, segment} <- Config.admin_label_presets() do
          assert String.contains?(block, inspect(preset)),
                 "block does not mention #{inspect(preset)}"

          assert String.contains?(block, ~s(admin_path: "/#{segment}")),
                 "block does not pair #{inspect(preset)} with /#{segment}"
        end
      end

      test "carries the marker the idempotency check looks for" do
        # `add_admin_label_options/1` skips when this string is already in the
        # file. If the two drift, every update appends another copy.
        assert String.contains?(
                 AdminLabelConfig.block(),
                 "# PhoenixKit — what to call the admin area"
               )
      end

      test "shows both the preset form and the derived-from-admin_path form" do
        block = AdminLabelConfig.block()
        assert String.contains?(block, "config :phoenix_kit, admin_panel_label: :workspace")
        assert String.contains?(block, ~s(config :phoenix_kit, admin_path: "/backoffice"))
      end
    end
  end
end
