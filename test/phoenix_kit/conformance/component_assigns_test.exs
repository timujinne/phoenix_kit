defmodule PhoenixKit.Conformance.ComponentAssignsTest do
  @moduledoc """
  Two halves. The fixture corpus under `test/fixtures/component_assigns/` pins
  the analyzer's policy: it must catch the og#7 shape and must NOT flag any of
  the legitimate patterns a naive scan trips over — each fixture is a real
  pattern from this tree (self-assign chains, slots, no-attr components,
  opaque helpers, `assigns_to_attributes`, prose with `@`-words). The live
  half runs the analyzer over core's own `lib/`, which is both the guard for
  core and the proof the policy holds on several hundred real files.

  Every fixture is asserted to PARSE before it is judged: an unparsable
  fixture yields no violations, which would let a must-be-ignored case pass
  vacuously — that failure mode bit the first version of this corpus.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Conformance.ComponentAssigns

  @fixture_dir Path.expand("../../fixtures/component_assigns", __DIR__)

  # file => violations expected as {component, assign}; [] = must be ignored.
  @expected %{
    "og7_shape.ex" => [{:modal, :missing}],
    "css_at_rules.ex" => [{:styled, :brand}],
    "code_example_sigils.ex" => [],
    "text_mention.ex" => [],
    "unary_minus.ex" => [{:refund, :amount}],
    "nested_interpolation.ex" => [{:chip, :selected}, {:chip, :variant}],
    "receiver_map_put.ex" => [{:avatar, :src}],
    "discarded_assign.ex" => [{:card, :ready}],
    "with_bind.ex" => [],
    "attr_then_deprecated.ex" => [{:old_badge, :missing}],
    "interp_read.ex" => [{:hand, :other_deg}],
    "self_assign.ex" => [],
    "slots_and_reserved.ex" => [],
    "no_attr_component.ex" => [],
    "render_skipped.ex" => [],
    "prose_and_emails.ex" => [],
    "map_merge_literal.ex" => [],
    "multi_clause.ex" => [],
    "heex_comment.ex" => [],
    "opaque_helper.ex" => [],
    "spread_component.ex" => []
  }

  test "every fixture parses — an unparsable fixture passes vacuously" do
    unparsable =
      for {name, _} <- @expected,
          path = Path.join(@fixture_dir, name),
          not match?({:ok, _}, Code.string_to_quoted(File.read!(path))),
          do: name

    assert unparsable == [],
           "fixture(s) do not parse, so their expectations prove nothing: #{inspect(unparsable)}"
  end

  test "every fixture COMPILES through the real HEEx engine" do
    # `Code.string_to_quoted` accepts a template the HEEx compiler rejects, so
    # parse-asserting alone lets a fixture encode an impossible oracle. This
    # compiles each fixture for real (which also runs Phoenix's own call-site
    # validation over them).
    Code.put_compiler_option(:ignore_module_conflict, true)

    on_exit(fn -> Code.put_compiler_option(:ignore_module_conflict, false) end)

    failures =
      for {name, _} <- @expected,
          path = Path.join(@fixture_dir, name),
          {result, _diagnostics} =
            Code.with_diagnostics(fn ->
              try do
                Code.compile_string(File.read!(path), path)
                :ok
              rescue
                e -> {:compile_error, Exception.message(e)}
              end
            end),
          result != :ok,
          do: {name, result}

    assert failures == [],
           Enum.map_join(failures, "\n", fn {name, {_, msg}} -> "#{name}: #{msg}" end)
  end

  test "the corpus is fully enumerated — a stray fixture is judged by nobody" do
    on_disk = @fixture_dir |> File.ls!() |> Enum.sort()
    listed = @expected |> Map.keys() |> Enum.sort()

    assert on_disk == listed
  end

  test "catches the bug shape and tolerates every legitimate pattern" do
    mismatches =
      for {name, expected} <- Enum.sort(@expected),
          path = Path.join(@fixture_dir, name),
          found =
            [path]
            |> ComponentAssigns.violations()
            |> Enum.map(&{&1.component, &1.assign})
            |> Enum.sort(),
          found != Enum.sort(expected),
          do: {name, Enum.sort(expected), found}

    assert mismatches == [],
           Enum.map_join(mismatches, "\n", fn {name, expected, found} ->
             "#{name}: expected #{inspect(expected)}, got #{inspect(found)}"
           end)
  end

  test "the :allow escape hatch suppresses exactly the listed assign" do
    path = Path.join(@fixture_dir, "og7_shape.ex")

    assert [] = ComponentAssigns.violations([path], allow: %{"og7_shape.ex" => [:missing]})

    assert [_] =
             ComponentAssigns.violations([path], allow: %{"og7_shape.ex" => [:something_else]})

    assert [_] = ComponentAssigns.violations([path], allow: %{"other_file.ex" => [:missing]})
  end

  test "core's own components read nothing they do not declare or assign" do
    violations =
      "lib/**/*.ex"
      |> Path.wildcard()
      |> ComponentAssigns.violations()

    assert violations == [],
           """
           #{length(violations)} undeclared assign read(s) in core:

           #{Enum.map_join(violations, "\n", &"  - #{&1.file}:#{&1.line} #{&1.component}/1 reads @#{&1.assign}")}

           Inside a function component `@x` reads that component's own assigns;
           an assign neither declared (attr/slot) nor assigned in the body
           raises KeyError when its branch renders, and the compiler cannot see
           it. Declare it and pass it at the call site — or, if this component
           does something the analysis cannot follow, add it to the `:allow`
           option with a comment saying why.
           """
  end
end
