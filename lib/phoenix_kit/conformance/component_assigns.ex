defmodule PhoenixKit.Conformance.ComponentAssigns do
  @moduledoc """
  Static check: a HEEx function component must not read an assign it neither
  declares nor assigns itself.

  Inside a function component, `@x` reads that component's OWN assigns. An
  assign that is neither declared as an `attr`/`slot` nor put there in the
  body raises `KeyError` when — and only when — the branch reading it renders.
  The compiler says nothing: Phoenix's declarative-assigns validation checks
  the CALL SITE (unknown attrs passed, required attrs missing) and never
  inspects the callee body, deliberately, because bodies may compute assigns
  dynamically. Verified empirically: the body-read shape produces zero
  diagnostics while the call-site shape warns.

  That silence let `phoenix_kit_open_graph`'s assignment modal ship a
  `KeyError :preview_loading` behind an `:if={...}` guard for four releases
  (BeamLabEU/phoenix_kit_open_graph#7). This module is the tree-wide guard for
  the class; one repo's render test covers one branch of one component, while
  every module in this ecosystem compiles the same blind spot.

  ## Policy — deliberately conservative

  A guard that cries wolf gets deleted, so v1 only reports what it can defend:

    * **Only components that opt into declarative assigns** — at least one
      `attr`/`slot` immediately above the definition. A component with no
      declarations legitimately receives whatever its callers pass; judging it
      requires call-site analysis this check does not do.
    * **`render/1` is skipped** — LiveView/extracted-template modules read the
      socket's assigns, which are not declared per-component.
    * **Self-assigned counts as declared — only via a rebind**: the template
      reads whatever the `assigns` VAR holds when `~H` runs, and keys enter it
      only through `assigns = ...`. So keys are collected exclusively from the
      right-hand side of such rebinds (`assign/2,3`, `assign_new/3`,
      literal-key `Map.put/3`, literal-map `Map.merge/2`, rooted at `assigns`,
      straight or piped). A DISCARDED `assign(assigns, :x, v)` feeds nothing
      and donates nothing, and `Map.put(assigns.user, :src, ...)` puts a key
      into a sub-map, not into assigns.
    * **Reserved assigns** (`@inner_block`, `@myself`, `@rest`, `@flash`,
      `@socket`, and LiveView's internals) always pass, as do declared slot
      names.
    * **Only code is scanned, ever**: balanced `{...}` expressions outside
      `<style>`, plus `<%= ... %>` blocks everywhere (those interpolate even
      inside `<style>`, where `{...}` and `\#{...}` stay literal character
      data). Prose, emails, CSS at-rules and showcase snippets are never
      looked at, rather than stripped-and-hopefully-not-missed. Within a code
      segment, string/sigil literals are removed and their `\#{...}`
      interpolations recursed into — nested ones included.
    * **Escape hatch**: `allow: %{"file_suffix.ex" => [:assign]}` for a
      component doing something the analysis cannot follow
      (`assigns_to_attributes/2`, dynamic merge, macro-generated bodies).
      Allowlisting is a documented decision, not a silent skip.

  ## Usage

      violations =
        PhoenixKit.Conformance.ComponentAssigns.violations(
          Path.wildcard("lib/**/*.ex")
        )

      assert violations == []

  Each violation is `%{file:, line:, component:, assign:}`. The paired test in
  this repo runs it over core's own `lib/`; sibling modules can do the same
  once their core pin ships this module, or be swept from a workspace script
  in the meantime.
  """

  @reserved [
    :inner_block,
    :myself,
    :rest,
    :flash,
    :socket,
    :__changed__,
    :__given__,
    :streams,
    :live_action,
    :uploads
  ]

  @type violation :: %{file: String.t(), line: pos_integer(), component: atom(), assign: atom()}

  @doc """
  Scans `paths` (a list of `.ex` files) and returns every undeclared read.

  Options:

    * `:allow` — map of file suffix => list of assign atoms to tolerate there.
  """
  @spec violations([Path.t()], keyword()) :: [violation()]
  def violations(paths, opts \\ []) do
    allow = Keyword.get(opts, :allow, %{})

    paths
    |> Enum.sort()
    |> Enum.flat_map(&file_violations/1)
    |> Enum.reject(fn v ->
      Enum.any?(allow, fn {suffix, assigns} ->
        String.ends_with?(v.file, suffix) and v.assign in assigns
      end)
    end)
  end

  defp file_violations(path) do
    with {:ok, source} <- File.read(path),
         {:ok, ast} <- Code.string_to_quoted(source, emit_warnings: false) do
      ast
      |> collect_components()
      |> Enum.flat_map(&component_violations(&1, path))
    else
      # An unreadable or unparsable file is the compiler's problem to report,
      # not this check's.
      _ -> []
    end
  end

  # ── Component discovery ────────────────────────────────────────────────────
  #
  # Walks each module body in order, accumulating attr/slot declarations and
  # attaching them to the next function definition — the same adjacency
  # Phoenix.Component itself uses. Later clauses of the same name/arity join
  # the same component (attrs are declared once, above the first clause).

  defp collect_components(ast) do
    {_, components} =
      Macro.prewalk(ast, [], fn
        {:defmodule, _, [_, [do: body]]} = node, acc ->
          {node, acc ++ module_components(body)}

        node, acc ->
          {node, acc}
      end)

    components
  end

  defp module_components(body) do
    statements =
      case body do
        {:__block__, _, statements} -> statements
        single -> [single]
      end

    {components, _pending} =
      Enum.reduce(statements, {%{}, {MapSet.new(), 0}}, fn statement, {components, pending} ->
        scan_statement(statement, components, pending)
      end)

    components
    |> Map.values()
    |> Enum.filter(&(&1.declared_any? and &1.name != :render))
  end

  defp scan_statement(statement, components, {pending, pending_count} = pending_state) do
    case statement do
      {decl, _, [name | _]} when decl in [:attr, :slot] and is_atom(name) ->
        {components, {MapSet.put(pending, name), pending_count + 1}}

      {def_kind, meta, [head, [do: fn_body] | _]} when def_kind in [:def, :defp] ->
        case assigns_component_head(head) do
          {name, 1} ->
            key = {name, 1}

            component =
              Map.get(components, key, %{
                name: name,
                line: meta[:line] || 1,
                declared: MapSet.new(@reserved),
                declared_any?: false,
                bodies: []
              })

            component = %{
              component
              | declared: MapSet.union(component.declared, pending),
                declared_any?: component.declared_any? or pending_count > 0,
                bodies: [fn_body | component.bodies]
            }

            {Map.put(components, key, component), {MapSet.new(), 0}}

          _ ->
            {components, {MapSet.new(), 0}}
        end

      _ ->
        # @doc, specs, moduledocs etc. sit between attrs and the def without
        # breaking the association; anything else clears it, matching Phoenix.
        if doc_like?(statement),
          do: {components, pending_state},
          else: {components, {MapSet.new(), 0}}
    end
  end

  # ANY module attribute between an attr/slot and its def is non-clearing:
  # Phoenix keeps pending declarations until the next function definition, and
  # @doc / @spec / @impl / @deprecated / @dialyzer all legitimately sit there.
  defp doc_like?({:@, _, _}), do: true
  defp doc_like?(_), do: false

  # A function head of exactly one argument that is, or binds, `assigns`.
  defp assigns_component_head({:when, _, [head | _]}), do: assigns_component_head(head)

  defp assigns_component_head({name, _, [arg]}) when is_atom(name) do
    if assigns_arg?(arg), do: {name, 1}, else: nil
  end

  defp assigns_component_head(_), do: nil

  defp assigns_arg?({:assigns, _, context}) when is_atom(context), do: true
  defp assigns_arg?({:=, _, [left, right]}), do: assigns_arg?(left) or assigns_arg?(right)
  defp assigns_arg?(_), do: false

  # ── Per-component analysis ─────────────────────────────────────────────────

  defp component_violations(component, path) do
    if Enum.any?(component.bodies, &opaque?/1) do
      # The body rebinds `assigns` through something this analysis cannot
      # follow — a local helper, a dynamic merge, `assigns_to_attributes/2`.
      # The declared set is unknowable, so the component is skipped rather
      # than guessed at: a guard that cries wolf gets deleted.
      []
    else
      do_component_violations(component, path)
    end
  end

  defp do_component_violations(component, path) do
    declared =
      component.bodies
      |> Enum.reduce(component.declared, fn body, acc ->
        MapSet.union(acc, rebind_assigned_keys(body))
      end)

    component.bodies
    |> Enum.flat_map(&templates/1)
    |> Enum.flat_map(fn {template, line} ->
      template
      |> template_reads()
      |> Enum.reject(&MapSet.member?(declared, &1))
      |> Enum.map(&%{file: path, line: line, component: component.name, assign: &1})
    end)
    |> Enum.uniq_by(&{&1.component, &1.assign})
  end

  # ── Opaqueness ─────────────────────────────────────────────────────────────
  #
  # `assigns` rebound through anything other than the recognized
  # key-transparent calls makes the declared set unknowable. Recognized:
  # `assign`/`assign_new` (bare or Phoenix.Component-qualified, straight or
  # piped), `Map.put` with a literal atom key, and `Map.merge` with a literal
  # map. Everything else — a local `prepare_assigns(assigns)` helper, a
  # variable-keyed put, `assigns_to_attributes/2` — marks the component
  # unanalyzable.

  defp opaque?(body) do
    {_, opaque} =
      Macro.prewalk(body, false, fn
        {op, _, [lhs, rhs]} = node, acc when op in [:=, :<-] ->
          if assigns_arg?(lhs) and not transparent_chain?(rhs),
            do: {node, true},
            else: {node, acc}

        {:assigns_to_attributes, _, args} = node, _acc when is_list(args) ->
          {node, true}

        {{:., _, [_, :assigns_to_attributes]}, _, _} = node, _acc ->
          {node, true}

        node, acc ->
          {node, acc}
      end)

    opaque
  end

  defp transparent_chain?({:assigns, _, context}) when is_atom(context), do: true

  defp transparent_chain?({:|>, _, [left, right]}),
    do: transparent_chain?(left) and piped_transparent_call?(right)

  defp transparent_chain?(node), do: rooted_transparent_call?(node)

  # A PIPED stage receives its receiver from the pipe, so its args start at the
  # key: `|> assign(:x, v)` arrives as {:assign, _, [:x, v]}. Judged without a
  # receiver — the chain root was already checked.
  defp piped_transparent_call?({fun, _, args})
       when fun in [:assign, :assign_new] and is_list(args),
       do: true

  defp piped_transparent_call?(
         {{:., _, [{:__aliases__, _, [:Phoenix, :Component]}, fun]}, _, args}
       )
       when fun in [:assign, :assign_new] and is_list(args),
       do: true

  defp piped_transparent_call?({{:., _, [{:__aliases__, _, [:Map]}, :put]}, _, [key, _value]}),
    do: is_atom(key)

  defp piped_transparent_call?({{:., _, [{:__aliases__, _, [:Map]}, :merge]}, _, [{:%{}, _, _}]}),
    do: true

  defp piped_transparent_call?(_), do: false

  # A DIRECT call carries its receiver as the first argument, and must be
  # ROOTED at `assigns`: `assigns = Map.merge(other, %{...})` derives the
  # template's assigns from `other`, which this analysis cannot follow — that
  # is opaque even though the merge has literal keys.
  defp rooted_transparent_call?({fun, _, [receiver | _]}) when fun in [:assign, :assign_new],
    do: assigns_arg?(receiver)

  defp rooted_transparent_call?(
         {{:., _, [{:__aliases__, _, [:Phoenix, :Component]}, fun]}, _, [receiver | _]}
       )
       when fun in [:assign, :assign_new],
       do: assigns_arg?(receiver)

  defp rooted_transparent_call?(
         {{:., _, [{:__aliases__, _, [:Map]}, :put]}, _, [receiver, key, _value]}
       ),
       do: assigns_arg?(receiver) and is_atom(key)

  defp rooted_transparent_call?(
         {{:., _, [{:__aliases__, _, [:Map]}, :merge]}, _, [receiver, {:%{}, _, _}]}
       ),
       do: assigns_arg?(receiver)

  defp rooted_transparent_call?(_), do: false

  # Keys enter the template's assigns ONLY through `assigns = ...` rebinds —
  # the sigil reads the var, not the history of calls — so collection walks the
  # body for rebind nodes and harvests keys from their right-hand sides alone.
  # Two review-caught bugs shaped this: receiver-blind collection let
  # `Map.put(assigns.user, :src, ...)` hide a real `@src` KeyError, and
  # body-wide collection let a DISCARDED `assign(assigns, :ready, true)` donate
  # a key it never delivered. Rootedness is still enforced within the rhs.
  defp rebind_assigned_keys(body) do
    {_, keys} =
      Macro.prewalk(body, MapSet.new(), fn
        # `assigns <- assign(...)` inside a `with` binds the var exactly like
        # `=` does — the AST operator differs, the semantics don't.
        {op, _, [lhs, rhs]} = node, acc when op in [:=, :<-] ->
          if assigns_arg?(lhs),
            do: {node, MapSet.union(acc, self_assigned_keys(rhs))},
            else: {node, acc}

        node, acc ->
          {node, acc}
      end)

    keys
  end

  defp self_assigned_keys(body) do
    {_, keys} =
      Macro.prewalk(body, MapSet.new(), fn
        # Piped stage: `<assigns-rooted chain> |> assign/assign_new/Map.put/...`
        {:|>, _, [left, {fun, _, args}]} = node, acc
        when fun in [:assign, :assign_new] and is_list(args) ->
          if assigns_rooted?(left),
            do: {node, MapSet.union(acc, keys_from_args(args))},
            else: {node, acc}

        {:|>, _, [left, {{:., _, [_, fun]}, _, args}]} = node, acc
        when fun in [:assign, :assign_new, :put, :merge] and is_list(args) ->
          if assigns_rooted?(left),
            do: {node, MapSet.union(acc, keys_from_args(args))},
            else: {node, acc}

        # Direct call: the receiver is the first argument.
        {fun, _, [receiver | rest]} = node, acc when fun in [:assign, :assign_new] ->
          if assigns_rooted?(receiver),
            do: {node, MapSet.union(acc, keys_from_args(rest))},
            else: {node, acc}

        {{:., _, [_, fun]}, _, [receiver | rest]} = node, acc
        when fun in [:assign, :assign_new, :put, :merge] ->
          if assigns_rooted?(receiver),
            do: {node, MapSet.union(acc, keys_from_args(rest))},
            else: {node, acc}

        node, acc ->
          {node, acc}
      end)

    keys
  end

  # The chain root: `assigns` itself, or a pipe/call whose own receiver is
  # rooted there. `assigns.user` (a dot ACCESS) is deliberately not a root —
  # putting a key into a sub-map does not put it into assigns.
  defp assigns_rooted?({:assigns, _, context}) when is_atom(context), do: true
  defp assigns_rooted?({:|>, _, [left, _]}), do: assigns_rooted?(left)

  defp assigns_rooted?({fun, _, [receiver | _]}) when fun in [:assign, :assign_new],
    do: assigns_rooted?(receiver)

  defp assigns_rooted?({{:., _, [_, fun]}, _, [receiver | _]})
       when fun in [:assign, :assign_new, :put, :merge],
       do: assigns_rooted?(receiver)

  defp assigns_rooted?(_), do: false

  defp keys_from_args(args) do
    Enum.reduce(args, MapSet.new(), fn
      key, acc when is_atom(key) and not is_nil(key) and not is_boolean(key) ->
        MapSet.put(acc, key)

      [{key, _} | _] = keyword, acc when is_atom(key) ->
        if Keyword.keyword?(keyword),
          do: MapSet.union(acc, MapSet.new(Keyword.keys(keyword))),
          else: acc

      {:%{}, _, pairs}, acc when is_list(pairs) ->
        literal_keys = for {key, _} <- pairs, is_atom(key), do: key
        MapSet.union(acc, MapSet.new(literal_keys))

      _, acc ->
        acc
    end)
  end

  # Every ~H template in the body, with its source line.
  defp templates(body) do
    {_, found} =
      Macro.prewalk(body, [], fn
        {:sigil_H, meta, [{:<<>>, _, [template]}, _]} = node, acc when is_binary(template) ->
          {node, [{template, meta[:line] || 1} | acc]}

        node, acc ->
          {node, acc}
      end)

    found
  end

  # ── Template scanning ──────────────────────────────────────────────────────
  #
  # SEGMENT-BASED: only text that HEEx evaluates as code is ever scanned —
  # balanced `{...}` expressions outside `<style>`, and `<%= ... %>` / `<% %>`
  # blocks everywhere (they interpolate even inside `<style>`, where `{...}`
  # and `#{...}` stay literal character data). Prose, CSS at-rules, static
  # attribute text and showcase snippets are simply never looked at, instead
  # of being stripped and hopefully not missed — the first strip-based version
  # both flagged an `@mention` in a text node and swallowed a real
  # `<%= @brand %>` inside a style block (caught by external review).

  @heex_comment ~r/<%!--.*?--%>|<!--.*?-->/s
  @eex_block ~r/<%=?\s(.*?)%>/s
  @style_block ~r/<style[^>]*>.*?<\/style>/s
  # Sigil literals with non-quote delimiters (`~s|...|`); quote-delimited ones
  # fall to the string strip.
  @sigil_literal ~r/~[a-zA-Z]\|[^|]*\||~[a-zA-Z]\([^)]*\)|~[a-zA-Z]\[[^\]]*\]/s
  @string_literal ~r/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/s
  # Inside a code segment `@name` is a read unless glued to a word/dot —
  # no `%+-` exclusions: `-@amount` is a real read, and emails are prose,
  # which segment extraction already excluded.
  @assign_read ~r/(?<![\w.])@([a-z_][a-zA-Z0-9_?!]*)/

  defp template_reads(template) do
    without_comments = Regex.replace(@heex_comment, template, " ")

    eex_segments =
      @eex_block
      |> Regex.scan(without_comments, capture: :all_but_first)
      |> Enum.map(&hd/1)

    non_style =
      without_comments
      |> then(&Regex.replace(@eex_block, &1, " "))
      |> then(&Regex.replace(@style_block, &1, " "))

    (eex_segments ++ brace_segments(non_style))
    |> Enum.flat_map(&code_reads/1)
    |> Enum.uniq()
  end

  # Reads within one code segment: scan it with string/sigil literals removed,
  # then recurse into each `#{...}` interpolation — whose contents are code
  # again, strings-with-interpolations included (`"bg-#{@variant}-500"`).
  defp code_reads(segment) do
    stripped =
      segment
      |> then(&Regex.replace(@sigil_literal, &1, " "))
      |> then(&Regex.replace(@string_literal, &1, " "))

    direct =
      @assign_read
      |> Regex.scan(stripped, capture: :all_but_first)
      |> Enum.map(fn [name] -> String.to_atom(name) end)

    nested = segment |> interpolation_segments() |> Enum.flat_map(&code_reads/1)

    direct ++ nested
  end

  # ── Balanced-region extraction ─────────────────────────────────────────────
  #
  # A character walk, because regex cannot pair nested braces:
  # `class={"#{if @selected, do: "bg-#{@variant}-500"}"}` is ONE expression.
  # Braces inside string literals do not count toward the balance, escapes are
  # honoured, and an unbalanced template yields whatever complete regions it
  # has — the HEEx compiler owns rejecting malformed templates.

  defp brace_segments(text), do: extract_regions(text, "{")
  defp interpolation_segments(text), do: extract_regions(text, "\#{")

  defp extract_regions(text, opener) do
    walk_for_opener(text, opener, [])
  end

  defp walk_for_opener("", _opener, acc), do: Enum.reverse(acc)

  defp walk_for_opener(text, opener, acc) do
    case String.split(text, opener, parts: 2) do
      [_all] ->
        Enum.reverse(acc)

      [_before, rest] ->
        case take_balanced(rest) do
          {region, remainder} -> walk_for_opener(remainder, opener, [region | acc])
          :unbalanced -> Enum.reverse(acc)
        end
    end
  end

  # The walk keeps a CONTEXT STACK, because strings and interpolations nest:
  # in `"bg-#{if @a, do: "x"}-500"` the outer string suspends brace counting,
  # the `#{` resumes it in a fresh code frame, an inner string suspends again,
  # and each `}`/`"` closes exactly the frame that opened it. Frames are
  # `{:code, depth}` / `:double` / `:single`; the region is complete when the
  # OUTERMOST code frame's depth hits zero.
  defp take_balanced(text), do: walk_stack(text, [{:code, 1}], [])

  defp walk_stack("", _stack, _acc), do: :unbalanced

  defp walk_stack(<<char::utf8, rest::binary>>, [top | _] = stack, acc) do
    chunk = <<char::utf8>>

    case top do
      {:code, _depth} -> code_step(chunk, rest, stack, acc)
      _string -> string_step(chunk, rest, stack, acc)
    end
  end

  defp code_step("{", rest, [{:code, depth} | below], acc),
    do: walk_stack(rest, [{:code, depth + 1} | below], ["{" | acc])

  defp code_step("}", rest, [{:code, 1}], acc),
    do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  # Closing an interpolation frame: the enclosing string resumes.
  defp code_step("}", rest, [{:code, 1} | below], acc), do: walk_stack(rest, below, ["}" | acc])

  defp code_step("}", rest, [{:code, depth} | below], acc),
    do: walk_stack(rest, [{:code, depth - 1} | below], ["}" | acc])

  defp code_step("\"", rest, stack, acc), do: walk_stack(rest, [:double | stack], ["\"" | acc])
  defp code_step("'", rest, stack, acc), do: walk_stack(rest, [:single | stack], ["'" | acc])
  defp code_step(chunk, rest, stack, acc), do: walk_stack(rest, stack, [chunk | acc])

  # Escapes hide the next character from the walk entirely.
  defp string_step("\\", rest, stack, acc) do
    case rest do
      <<next::utf8, tail::binary>> -> walk_stack(tail, stack, [<<next::utf8>>, "\\" | acc])
      "" -> :unbalanced
    end
  end

  defp string_step("\"", rest, [:double | below], acc), do: walk_stack(rest, below, ["\"" | acc])
  defp string_step("'", rest, [:single | below], acc), do: walk_stack(rest, below, ["'" | acc])

  # `#{` inside a double-quoted string opens a fresh code frame; its closing
  # brace pops back to the string.
  defp string_step("\#", <<"{", tail::binary>>, [:double | _] = stack, acc),
    do: walk_stack(tail, [{:code, 1} | stack], ["\#{" | acc])

  defp string_step(chunk, rest, stack, acc), do: walk_stack(rest, stack, [chunk | acc])
end
