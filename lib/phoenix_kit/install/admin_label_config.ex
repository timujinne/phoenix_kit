# Igniter-only helper: every caller is a `mix phoenix_kit.*` igniter task,
# which is itself guarded the same way. Igniter is an OPTIONAL dependency
# (see mix.exs), so a host that scopes it to `only: [:dev, :test]` compiles
# :prod without it.
if Code.ensure_loaded?(Igniter) do
  defmodule PhoenixKit.Install.AdminLabelConfig do
    @moduledoc """
    Writes the admin-area naming options into the host's `config/config.exs`,
    commented out.

    ## Why a comment block rather than a doc link

    `:admin_panel_label` takes one of a closed set of preset atoms
    (`PhoenixKit.Config.admin_label_presets/0`). A developer cannot guess that
    vocabulary, and the two places it was written down — the settings page and
    the CHANGELOG — are not where anyone stands when they go to change it. The
    admin settings page can now simply say "set it in config.exs", because the
    list is waiting there when they arrive.

    Every line is a comment, so the block is inert: it cannot change behaviour,
    cannot conflict with anything the host writes, and does not care where in
    the file it lands. That is what makes appending safe even after
    `import_config`.

    Idempotent via `@marker` — `mix phoenix_kit.update` runs this too, so a host
    that installed before this existed picks the block up, and one that already
    has it (or has deleted it on purpose) is left alone.
    """

    @marker "# PhoenixKit — what to call the admin area"

    @doc """
    Appends the commented options block to `config/config.exs`.

    No-op when the file is missing, when the block is already there, or when
    the host has uncommented `admin_panel_label` for themselves — in the last
    case they have already made the choice this block exists to explain.
    """
    def add_admin_label_options(igniter) do
      if File.exists?("config/config.exs") do
        Igniter.update_file(igniter, "config/config.exs", fn source ->
          content = Rewrite.Source.get(source, :content)

          if skip?(content) do
            source
          else
            Rewrite.Source.update(source, :content, content <> block())
          end
        end)
      else
        igniter
      end
    rescue
      _ ->
        igniter
    end

    defp skip?(content) do
      String.contains?(content, @marker) or active_admin_panel_label?(content)
    end

    # An UNCOMMENTED `admin_panel_label:` anywhere in the file. Checked line by
    # line rather than with `String.contains?/2` so the block's own commented
    # examples — and a host's — never count as the host having chosen.
    defp active_admin_panel_label?(content) do
      content
      |> String.split("\n")
      |> Enum.any?(fn line ->
        trimmed = String.trim(line)
        not String.starts_with?(trimmed, "#") and String.contains?(trimmed, "admin_panel_label:")
      end)
    end

    @doc false
    # Public only so the suite can assert the two properties this block's
    # safety rests on: that it covers every preset, and that every line of it
    # is a comment. The latter is what makes appending it after
    # `import_config` harmless.
    def block do
      presets =
        PhoenixKit.Config.admin_label_presets()
        |> Enum.map_join("\n", fn {preset, segment} ->
          "#     #{String.pad_trailing(inspect(preset), 16)} #{label_hint(preset)}" <>
            String.duplicate(" ", max(1, 18 - String.length(label_hint(preset)))) <>
            "pairs with admin_path: \"/#{segment}\""
        end)

      """

      #{@marker}
      #
      # The admin header and the account menu both say "Admin Panel" by default.
      # To call it something else AND keep it translated for every visitor, pick
      # one of these built-in names:
      #
      #{presets}
      #
      #     config :phoenix_kit, admin_panel_label: :workspace
      #
      # Leave it unset and the name is derived from :admin_path, so renaming the
      # URL renames the wording with it — one key, never out of step:
      #
      #     config :phoenix_kit, admin_path: "/backoffice"   # URL and header
      #
      # A free-text string works too, for a brand name no preset covers:
      #
      #     config :phoenix_kit, admin_panel_label: "Acme HQ"
      #
      # ...but it is NOT translated. One string, shown to every visitor in every
      # language. That is what the presets above are for.
      """
    end

    # The English wording each preset renders to, for the comment only. Kept as
    # plain strings rather than a `gettext/1` call: this is generated source
    # code in the host's repo, not UI, and it must read the same whatever locale
    # the developer running the installer happens to have.
    defp label_hint(:admin_panel), do: "\"Admin Panel\""
    defp label_hint(:dashboard), do: "\"Dashboard\""
    defp label_hint(:backoffice), do: "\"Backoffice\""
    defp label_hint(:console), do: "\"Console\""
    defp label_hint(:control_panel), do: "\"Control Panel\""
    defp label_hint(:workspace), do: "\"Workspace\""
    defp label_hint(:portal), do: "\"Portal\""
    defp label_hint(:my_account), do: "\"My Account\""
    defp label_hint(:management), do: "\"Management\""
    defp label_hint(:studio), do: "\"Studio\""
  end
end
