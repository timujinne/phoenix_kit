defmodule Mix.Tasks.Compile.PhoenixKitJsSourcesTest do
  @moduledoc """
  Unit tests for the pure content-generation + validation helpers of the
  `:phoenix_kit_js_sources` compiler (the IIFE wrapping, the merge line, the
  empty case, and the fail-loud guards). The full `run/1` does live module
  discovery in the host app and is exercised end-to-end by consumers, not here.
  """

  use ExUnit.Case, async: true

  alias Mix.Tasks.Compile.PhoenixKitJsSources, as: Compiler

  describe "build_content/1" do
    test "no specs emits NO merge line (no Object.assign syntax error)" do
      js = Compiler.build_content([])

      refute js =~ "Object.assign"
      assert js =~ "No external module declares js_sources/0"
    end

    test "the install-facts preamble is emitted even with no module bundles" do
      # It rides in this file because the file is already <script>-tagged in
      # every host's layout — a separate globals file would need a layout edit
      # and a `phoenix_kit.update` backfill to reach existing installs.
      js = Compiler.build_content([])

      assert js =~ "window.PHOENIX_KIT_PREFIX="
      assert js =~ "window.PHOENIX_KIT_CONSENT_AVAILABLE="
    end

    test "the preamble is also present alongside module bundles" do
      dir = tmp_dir!()
      file = Path.join(dir, "p.js")
      File.write!(file, "window.PHooks={}")
      spec = %{app: :p, file: "p.js", global: "PHooks", source: file}

      js = Compiler.build_content([spec])

      assert js =~ "window.PHOENIX_KIT_PREFIX="
      assert js =~ "Object.assign"
    end

    test "wraps each bundle in an IIFE and folds its global into PhoenixKitHooks" do
      dir = tmp_dir!()
      file = Path.join(dir, "a.js")
      File.write!(file, "window.AHooks={X:1}")
      spec = %{app: :a, file: "a.js", global: "AHooks", source: file}

      js = Compiler.build_content([spec])

      # IIFE wrapper isolates the bundle's top-level scope; leading ; guards ASI.
      assert js =~ ";(function(){"
      assert js =~ "})();"
      assert js =~ "window.AHooks={X:1}"
      # Merge folds the bundle's global into the host-spread global.
      assert js =~
               "window.PhoenixKitHooks=Object.assign(window.PhoenixKitHooks||{},window.AHooks||{});"
    end

    test "merges every distinct global into a single Object.assign" do
      dir = tmp_dir!()
      a = Path.join(dir, "a.js")
      b = Path.join(dir, "b.js")
      File.write!(a, "window.AHooks={}")
      File.write!(b, "window.BHooks={}")

      js =
        Compiler.build_content([
          %{app: :a, file: "a.js", global: "AHooks", source: a},
          %{app: :b, file: "b.js", global: "BHooks", source: b}
        ])

      assert js =~
               "Object.assign(window.PhoenixKitHooks||{},window.AHooks||{},window.BHooks||{});"
    end
  end

  describe "check_unique_globals/1" do
    test "passes when every bundle declares a distinct global" do
      specs = [
        %{app: :a, file: "a.js", global: "AHooks"},
        %{app: :b, file: "b.js", global: "BHooks"}
      ]

      assert Compiler.check_unique_globals(specs) == :ok
    end

    test "raises when two bundles share a global (would clobber each other)" do
      specs = [
        %{app: :a, file: "a.js", global: "Dup"},
        %{app: :b, file: "b.js", global: "Dup"}
      ]

      assert_raise Mix.Error, ~r/same window global/, fn ->
        Compiler.check_unique_globals(specs)
      end
    end
  end

  describe "normalize_entry/1" do
    test "passes a well-formed map through" do
      entry = %{app: :a, file: "a.js", global: "AHooks"}
      assert Compiler.normalize_entry(entry) == entry
    end

    test "raises on a malformed entry" do
      assert_raise Mix.Error, ~r/Invalid js_sources/, fn ->
        Compiler.normalize_entry(%{app: :a})
      end
    end

    test "raises when :global is not a valid JS identifier" do
      assert_raise Mix.Error, ~r/valid JavaScript/, fn ->
        Compiler.normalize_entry(%{app: :a, file: "a.js", global: "foo-bar"})
      end
    end
  end

  defp tmp_dir! do
    dir = Path.join(System.tmp_dir!(), "pk_js_sources_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
