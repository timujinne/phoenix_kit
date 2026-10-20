defmodule PhoenixKit.API.Executor do
  @moduledoc """
  The request flow of the machine API: what happens between "this key is
  authentic" and "here is the response".

  `PhoenixKit.API.Auth` has already done steps 1 to 3 of the flow (API
  switch, refusal of a credential in the URL, authentication). `execute/4` and
  `visible/2` do the rest and return their outcome; `call/4` and `list/2` are
  thin senders over them for the REST transport:

    4. **Tool visible.** The tool exists for this audience (`404 not_found`),
       its module is enabled (`404 module_disabled`), and the key's effective
       scopes include the tool's scope (`403 forbidden`). A tool listed in
       `api_disabled_tools`, or of a module listed in `api_disabled_modules`,
       does not exist for `PhoenixKit.API.Registry`, so it is `not_found` too.
    5. **Rate limit**, cost weighted (`PhoenixKit.API.RateLimit`, `cost/2`):
       a call costs 1 unit; only a **write** tool of the admin audience (not
       read-only) costs 1 per 50 rows of its longest top-level list, counted
       up to the tool's `max_items` (or, for a tool without one, up to 1000
       rows) at most, so a request that is refused for size cannot use up
       the key's budget. Reads and public tools cost 1 however long their
       lists are. A tool that needs another price (1 per
       query of a search batch) declares it with `Tool.cost`. The public
       audience pays 1 unit of its network bucket BEFORE the tool lookup (a
       miss in `Registry.find/2` costs about 2 ms, so a flood of unknown
       names must end in 429 without it). The caller's client token is read
       only after the lookup, because the tool declares which input field
       holds it (`Tool.client_token`): the call then pays its full price to
       the token's bucket (when it carries a token) and the rest of it (price
       minus 1) to the network bucket. So a call that the token's bucket
       refuses has already spent 1 unit of the network's. The admin audience
       is charged once, after the scope check, because its price depends on
       the tool. A call the lookup or the scope check refuses (unknown,
       hidden, forbidden or disabled-module tool) never reaches that charge,
       so it pays one unit
       instead: a key cannot loop on invented names for free. The answer is
       the same refusal, or `429` when the key's budget is spent; the refusal
       writes no audit entry.
    6. **Validate** the input against `max_items` and against the tool's
       `input_schema` **closed by `PhoenixKit.API.Validator.close_schema/2`**
       (so a schema that forgot `additionalProperties: false` still refuses
       unknown fields, the control fields included). `list/2` shows the
       closed schema (`input_schema/1`), the one `execute/4` validates
       against. Before that, over REST the `Idempotency-Key` header of a write
       call is merged into the input (`Flow.merge_header/1`), so it is
       validated like the field; MCP takes the key from the argument only.
    9. **Run** the handler, `apply(module, function, [input, ctx])`.
   10. **Log.** A call to a write tool (`annotations.read_only` is not
       `true`) from a key writes one `api.request` Activity entry: tool, key
       prefix, row count, outcome. Calls refused before step 6 (unknown tool,
       missing scope, rate limited) write nothing, so a refused request
       costs no write; so does a replay of a stored answer. The entry's
       outcome is `ok`, `error`, `preview` (a dry run), `confirmation_required`
       (the call asked for a code) or `pending_approval` (queued for an
       approver). The module logs its own domain changes.
   11. **Shape** the response: `200` with the handler's map as JSON, or a
       problem document (`PhoenixKit.API.Problem`).

  Steps 7 and 8 are `PhoenixKit.API.Flow`:

    7. **Idempotency** (`Flow.idempotency/1`): a write call with an
       `Idempotency-Key` claims it; a finished twin is answered from the
       store, a running twin is `409`.
    8. **Danger** (`Flow.gate/1`): `dry_run` answers the preview; a dangerous
       operation answers a preview and a confirmation code, or is queued for
       approval (a repeat of an operation that already waits gets the same
       approval back, marked with the replay header but not stored, and still
       audited); with a valid code it runs.

  Each step is one function taking and returning the request state, chained
  in `execute/4`. A step may also end the request with `{:done, state}`: the
  body is already set (a preview, a replay) and the handler does not run.
  The executor adds the control fields `dry_run`, `confirm_token` and
  `idempotency_key` to the schema of every write tool and closes every schema
  (`PhoenixKit.API.ControlFields`; a write tool with `replay: false` gets no
  `idempotency_key`). A read tool has none of them, so a client that sends one
  gets `422 validation_failed`: a field that would change what a write does is
  refused, never silently ignored.

  ## Scopes and work per request

  `PhoenixKit.API.Keys.verify/2` (called by `PhoenixKit.API.Auth`) has
  already computed the effective scopes of this request into `actor.scopes`
  (the key's scopes filtered by the owner's permissions right now, never
  cached). The executor **trusts those scopes and does not compute them
  again**: it would only repeat the owner lookup and the scope filtering.
  What a request still scans twice is the module registry
  (`ModuleRegistry.all_api_tools/0`: once inside `verify/2` to know the
  scopes that exist, once in `Registry.find/2`); that is two walks over a
  handful of modules, and sharing the result would need an API change in
  `Registry`, so 1a accepts it.

  ## The handler

  A tool's handler returns `{:ok, map}`, `{:ok, map, effects}` (the effects
  list is added to the response under `"effects"`) or
  `{:error, code, message, context}` (`code` is an atom from
  `PhoenixKit.API.Problem.statuses/0`: core's own codes plus those the
  module declares in `c:PhoenixKit.Module.api_problems/0`; an undeclared
  code answers 500). Anything else, and any exception,
  exit or throw, answers `500 internal_error` with a generic message; the
  detail goes to the log, never to the client.

  The context is a map:

    * `:actor` the `PhoenixKit.API.Actor`; `:scopes` its effective scopes;
    * `:scope`, the `PhoenixKit.Users.Auth.Scope` behind those scopes, for a handler that
      filters rows by the caller's rights: the key owner's full scope
      (`Scope.for_user(owner, narrow: false)`) for a key, the session's scope for a live
      session, `nil` for a public caller (a handler answers nothing it would filter by it).
      A key's own scopes do not narrow it: rows filtered by `ctx.scope` are the ones the
      owner sees, whatever the key's scopes;
    * `:audience`, `:language`, `:currency`, `:hosts`, `:base_url` (see
      `PhoenixKit.API.RequestContext`); `:base_url` is `nil` for a live session whose
      caller passed none;
    * `:request_id`;
    * `:dry_run?`, `true` while the danger gate asks for a preview (the handler
      must then write nothing and answer `{:preview, preview, fingerprint}`, where `fingerprint`
      is a hash of the current values the operation would touch: 1 to 64 bytes of UTF-8, e.g. a
      SHA-256 in hex; any other answer is a `500`);
    * `:approved_by_uuid`, the person who approved the operation (`nil` unless it
      runs from the approval queue), `:confirmation_uuid`, the confirmation code
      or approval row it runs under (`nil` for an ordinary call) and `:progress`,
      a one-argument function a long batch may call with its partial results. It also
      keeps an approved operation alive: one that runs longer than 15 minutes without
      calling it is marked `failed` (`interrupted`) by the stuck-operation sweep, so a
      long handler calls it at least every few minutes.

  ## On behalf of a live session

  `visible_for/3` and `execute_as/5` run the same flow in process, without a
  `Plug.Conn`, for a person's live browser session (`PhoenixKit.Users.Auth.SessionRef`,
  an `Actor` of kind `:user`). What differs from a key:

    * the scope is rebuilt from the session **on every call**
      (`SessionRef.scope_for_session/2`): a logged-out or revoked session, a blocked
      user, a user the web's account gate would stop (unconfirmed email, missing
      referral code), a session of another user, or a reference that is not a
      `{session_token_uuid, user_uuid}` pair is `401 unauthorized`, and the scope is
      narrowed to the role the session acts as;
    * the effective scopes are `PhoenixKit.API.Keys.held_scopes_of/1` of that scope, and
      the tool's own permission is checked too (`Scope.can?/2`); a tool without a
      permission (`system.*`, which describe the calling key) is not callable;
    * only read tools: `allow: :read` (the default, and the only value in this version)
      refuses a write tool (`PhoenixKit.API.ControlFields.write_tool?/1`) before
      validation and before `Flow.gate/1`, so nothing runs; `visible_for/3` lists none;
    * the request context comes from the `:request_context` option, not from a
      connection, and the host's `:api_request_context` hook (which expects a
      `Plug.Conn`) is not called;
    * the rate limit is the user's own bucket (`RateLimit.check_user/2`), shared by the
      user's sessions; `api_admin_enabled` does not apply (it switches the HTTP API);
    * reads are not audited, as for a key;
    * maintenance mode is not checked on this path: the web shows the maintenance layout
      at mount, where nothing that calls the Executor is rendered.

  The `{session_token_uuid, user_uuid}` pair is not a secret, but it is an in-process
  credential: whatever code passes it to `execute_as/5` or `visible_for/3` acts as that
  session. Take it only from the signed session of the LiveView that runs in that session
  (`SessionRef.from_session/1` in its connected mount), never from params or client events.
  """

  import Plug.Conn

  require Logger

  alias PhoenixKit.Activity
  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.ControlFields
  alias PhoenixKit.API.Flow
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Legacy
  alias PhoenixKit.API.LogSafe
  alias PhoenixKit.API.OutputShape
  alias PhoenixKit.API.Problem
  alias PhoenixKit.API.RateLimit
  alias PhoenixKit.API.Registry
  alias PhoenixKit.API.RequestContext
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.Validator
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.SessionRef
  alias PhoenixKit.Utils.IpAddress

  @empty_schema %{"type" => "object", "properties" => %{}, "additionalProperties" => false}

  # An admin write costs one unit per this many rows.
  @rows_per_unit 50

  # Rows charged at most for a write tool that declares no `max_items`.
  @default_max_billable_rows 1_000

  # How much of a client-chosen tool name an answer repeats.
  @clip_codepoints 100

  @typedoc "Response headers to send with an outcome: the rate-limit headers."
  @type headers :: [{String.t(), String.t()}]

  @typedoc """
  What `execute/4` returns: the handler's result (the decoded map and its JSON
  encoding) or the error in `PhoenixKit.API.Problem` terms, each with the
  headers of the rate limit.
  """
  @type outcome ::
          {:ok, %{result: map(), json: binary()}, headers()}
          | {:error, atom(), String.t(), map(), headers()}

  @doc """
  Runs tool `tool_name` for the actor `PhoenixKit.API.Auth` assigned, with
  `input` (the decoded request body), and sends the response.
  """
  @spec call(Plug.Conn.t(), Tool.audience(), String.t(), term()) :: Plug.Conn.t()
  def call(conn, audience, tool_name, input) do
    case execute(conn, audience, tool_name, input) do
      {:ok, %{json: json}, headers} ->
        send_json(conn, headers, json)

      {:error, code, detail, context, headers} ->
        send_problem(conn, headers, code, detail, context)
    end
  end

  @doc """
  Runs tool `tool_name` for the actor `PhoenixKit.API.Auth` assigned, with
  `input`, and **returns** the outcome instead of sending it. This is what
  `call/4` does, minus the HTTP response, and what the MCP transport uses.

  Returns `{:ok, %{result: map, json: binary}, headers}` or
  `{:error, code, detail, context, headers}` (`code` is an atom of
  `PhoenixKit.API.Problem.statuses/0`; `context` is the map the problem
  document carries). `headers` are the rate-limit headers when the request got
  as far as the limiter, else `[]`. The `api.request` audit entry of a write
  call is written here, before returning.

  The option `:resolve_name` is a function from the name as the caller gave it
  to the name of the tool to look up. It runs after the public charge, in the
  lookup step, so a name that costs registry walks to resolve is not resolved
  for a caller the limiter has already refused.

  The option `:idempotency_header` (default `true`) says whether the
  `Idempotency-Key` HTTP header is read. The REST transport reads it; MCP
  passes `false`, because an MCP client sends the key as the `idempotency_key`
  argument and a header on the transport request is not part of the call.
  """
  @spec execute(Plug.Conn.t(), Tool.audience(), String.t(), term(), keyword()) :: outcome()
  def execute(conn, audience, tool_name, input, opts \\ []) do
    state = new_state(conn, audience, tool_name, input, opts)

    with {:ok, state} <- require_actor(state),
         {:ok, state} <- charge_before_lookup(state),
         {:ok, state} <- find_tool(state),
         {:ok, state} <- take_scopes(state),
         {:ok, state} <- check_scope(state),
         {:ok, state} <- bind_client_token(state),
         {:ok, state} <- charge_after_lookup(state),
         {:ok, state} <- Flow.merge_header(state),
         {:ok, state} <- validate(state),
         {:ok, state} <- Flow.split_control(state),
         {:ok, state} <- Flow.idempotency(state),
         {:ok, state} <- resolve_request_context(state),
         {:ok, state} <- Flow.gate(state),
         {:ok, state} <- run(state) do
      complete(state)
    else
      {:done, state} -> complete(state)
      {:error, code, detail, context, state} -> refused(state, code, detail, context)
    end
  end

  @doc """
  Sends the list of tools the actor may call: name, title, description,
  scope, schemas and annotations. For the admin audience the list is
  filtered by the key's effective scopes.
  """
  @spec list(Plug.Conn.t(), Tool.audience()) :: Plug.Conn.t()
  def list(conn, audience) do
    case visible(conn, audience) do
      {:ok, tools, headers} ->
        body = encode(%{"tools" => Enum.map(tools, &describe/1), "count" => length(tools)})
        send_json(conn, headers, body)

      {:error, code, detail, context, headers} ->
        send_problem(conn, headers, code, detail, context)
    end
  end

  @doc """
  The tools the actor may call, as `list/2` shows them, **returned** instead
  of sent. For the admin audience: the tools whose scope the key effectively
  holds, plus the scope-less ones (`system.*`); for the public audience: every
  public tool. Costs one rate-limit unit, like `list/2`.
  """
  @spec visible(Plug.Conn.t(), Tool.audience()) ::
          {:ok, [Tool.t()], headers()} | {:error, atom(), String.t(), map(), headers()}
  def visible(conn, audience) do
    state = new_state(conn, audience, nil, %{}, [])

    with {:ok, state} <- require_actor(state),
         {:ok, state} <- take_scopes(state),
         {:ok, state} <- rate_limit(state) do
      {:ok, Registry.visible_tools(audience, visible_scopes(state)), state.headers}
    else
      {:error, code, detail, context, state} -> {:error, code, detail, context, state.headers}
    end
  end

  @doc """
  The tools the live session `session_ref` (`{session_token_uuid, user_uuid}`, see
  `PhoenixKit.Users.Auth.SessionRef`) may call, for the admin audience: the read tools
  whose scope the session's scope holds (`PhoenixKit.API.Keys.held_scopes_of/1`) and whose
  permission it holds. No write tool and no `system.*` tool. Costs one unit of the user's
  rate-limit bucket.

  Options: `:allow`, only `:read` (the default); any other value raises `ArgumentError`.

  Returns `{:ok, tools, headers}`, or `{:error, code, detail, context, headers}`
  (`:unauthorized` with `context.reason` from `t:SessionRef.refusal/0` when the session
  cannot act, `:rate_limited`).
  """
  @spec visible_for(SessionRef.t(), :admin, keyword()) ::
          {:ok, [Tool.t()], headers()} | {:error, atom(), String.t(), map(), headers()}
  def visible_for(session_ref, :admin, opts \\ []) do
    :read = allow!(opts)
    state = session_state(session_ref, nil, %{}, opts)

    with {:ok, state} <- session_actor(state),
         {:ok, state} <- take_scopes(state),
         {:ok, state} <- rate_limit(state) do
      tools =
        :admin
        |> Registry.visible_tools(state.scopes)
        |> Enum.filter(&session_may_call?(state.actor.scope, &1))

      {:ok, tools, state.headers}
    else
      {:error, code, detail, context, state} -> {:error, code, detail, context, state.headers}
    end
  end

  @doc """
  Runs tool `tool_name` with `input` on behalf of the live session `session_ref`
  (`{session_token_uuid, user_uuid}`), in process, and returns the outcome as
  `execute/5` does. The session's scope is rebuilt for this call; see "On behalf of a
  live session" above for what differs from a key.

  Options:

    * `:allow` - only `:read` (the default); a write tool is refused with `403
      forbidden` before anything runs. Any other value raises `ArgumentError`.
    * `:request_context` - keyword list: `:language`, `:base_url`, `:hosts`, `:currency`
      (the handler context, `PhoenixKit.API.RequestContext.from_options/1`),
      `:request_id` (the context's `:request_id`) and `:ip` (the actor's `ip`).
  """
  @spec execute_as(SessionRef.t(), :admin, String.t(), term(), keyword()) :: outcome()
  def execute_as(session_ref, :admin, tool_name, input, opts \\ []) do
    :read = allow!(opts)
    state = session_state(session_ref, tool_name, input, opts)

    with {:ok, state} <- session_actor(state),
         {:ok, state} <- find_tool(state),
         {:ok, state} <- take_scopes(state),
         {:ok, state} <- check_scope(state),
         {:ok, state} <- check_permission(state),
         {:ok, state} <- reads_only(state),
         {:ok, state} <- charge_after_lookup(state),
         {:ok, state} <- validate(state),
         {:ok, state} <- Flow.split_control(state),
         {:ok, state} <- Flow.idempotency(state),
         {:ok, state} <- Flow.gate(state),
         {:ok, state} <- run(state) do
      complete(state)
    else
      {:done, state} -> complete(state)
      {:error, code, detail, context, state} -> refused(state, code, detail, context)
    end
  end

  defp allow!(opts) do
    case Keyword.get(opts, :allow, :read) do
      :read ->
        :read

      other ->
        raise ArgumentError,
              "allow: #{inspect(other)} is not supported: a session may only read (allow: :read)"
    end
  end

  # --- state ----------------------------------------------------------------

  defp new_state(conn, audience, tool_name, input, opts) do
    audience
    |> base_state(tool_name, input, opts)
    |> Map.merge(%{conn: conn, actor: actor_for(conn, audience)})
  end

  # A call on behalf of a live session: no connection, so the request context is taken
  # from the options (never from the host hook, which expects a `Plug.Conn`) and the
  # actor is resolved from the session by `session_actor/1`.
  # A reference that is not a `{session_token_uuid, user_uuid}` pair names no session:
  # `session_actor/1` refuses it as gone.
  defp session_state(session_ref, tool_name, input, opts) do
    request = request_options(Keyword.get(opts, :request_context, []))

    :admin
    |> base_state(tool_name, input, idempotency_header: false)
    |> Map.merge(%{
      session_ref: session_pair(session_ref),
      client_ip: binary_option(request, :ip),
      request_id: binary_option(request, :request_id),
      request_context: RequestContext.from_options(request)
    })
  end

  defp session_pair({_token_uuid, _user_uuid} = session_ref), do: session_ref
  defp session_pair(_other), do: nil

  # Only `{atom, value}` pairs count: anything else in the list (or a list that is not a
  # keyword list at all) is dropped, so a malformed context gets the defaults.
  defp request_options(options) when is_list(options) or is_map(options),
    do: Enum.filter(options, &match?({key, _value} when is_atom(key), &1))

  defp request_options(_other), do: []

  defp binary_option(options, key) do
    case Keyword.get(options, key) do
      value when is_binary(value) -> value
      _other -> nil
    end
  end

  defp base_state(audience, tool_name, input, opts) do
    %{
      conn: nil,
      session_ref: nil,
      client_ip: nil,
      request_id: nil,
      audience: audience,
      name: tool_name,
      resolve_name: Keyword.get(opts, :resolve_name),
      idempotency_header?: Keyword.get(opts, :idempotency_header, true),
      input: input,
      rows: rows(input),
      actor: nil,
      tool: nil,
      scopes: [],
      headers: [],
      charged?: false,
      body: nil,
      control: %{},
      dry_run?: false,
      input_hash: nil,
      claim: nil,
      replayed?: false,
      held_again?: false,
      store?: true,
      outcome: nil,
      confirmation: nil,
      preview: nil,
      result: nil,
      request_context: nil
    }
  end

  defp actor_for(conn, :public) do
    case conn.assigns[:phoenix_kit_api_actor] do
      %Actor{} = actor -> actor
      _none -> %Actor{kind: :anonymous, ip: IpAddress.client_address(conn)}
    end
  end

  defp actor_for(conn, :admin), do: conn.assigns[:phoenix_kit_api_actor]

  # A public tool names the input field that holds its anonymous caller's token
  # (`Tool.client_token`), so the token can only be read once the tool is known. The raw
  # token is a credential: only its hash is kept on the actor, for rate limiting, the
  # scope of an idempotency key and the binding of a confirmation code.
  defp bind_client_token(
         %{audience: :public, tool: %Tool{client_token: field}, input: input, actor: actor} =
           state
       )
       when is_binary(field) do
    {:ok, %{state | actor: %{actor | client_token_hash: client_token_hash(input, field)}}}
  end

  defp bind_client_token(state), do: {:ok, state}

  defp client_token_hash(%{} = input, field) do
    case Map.get(input, field) do
      token when is_binary(token) and token != "" ->
        :crypto.hash(:sha256, token) |> Base.url_encode64(padding: false)

      _no_token ->
        nil
    end
  end

  defp client_token_hash(_input, _field), do: nil

  # A public tool built before `Tool.client_token` existed declares no field;
  # `PhoenixKit.API.Legacy` still finds the one it used, so such a tool keeps its limits,
  # its idempotency scope and its danger gate. The tool the request runs carries the
  # field it is read through.
  defp with_client_token(%Tool{client_token: nil} = tool),
    do: %{tool | client_token: Legacy.legacy_client_token(tool)}

  defp with_client_token(%Tool{} = tool), do: tool

  # --- steps ----------------------------------------------------------------

  defp require_actor(%{actor: %Actor{kind: :key}} = state), do: {:ok, state}
  defp require_actor(%{audience: :public, actor: %Actor{}} = state), do: {:ok, state}

  defp require_actor(state),
    do: {:error, :unauthorized, "Authentication is required.", %{}, state}

  # The scope of a live session, rebuilt for this call: the session must still be alive,
  # belong to the user named in the reference, and its user be active and pass the
  # account gate of the web (`SessionRef.scope_for_session/2`).
  defp session_actor(%{session_ref: {token_uuid, user_uuid}} = state) do
    case SessionRef.scope_for_session(token_uuid, user_uuid) do
      {:ok, %Scope{} = scope} ->
        actor = %Actor{
          kind: :user,
          user_uuid: scope.user.uuid,
          scopes: Keys.held_scopes_of(scope),
          scope: scope,
          ip: state.client_ip
        }

        {:ok, %{state | actor: actor}}

      {:error, reason} ->
        session_refused(state, reason)
    end
  end

  defp session_actor(state), do: session_refused(state, :session_gone)

  defp session_refused(state, reason),
    do: {:error, :unauthorized, session_refusal(reason), %{reason: reason}, state}

  defp session_refusal(:session_gone), do: "The session has ended."
  defp session_refusal(:mismatch), do: "The session belongs to another user."
  defp session_refusal(:inactive), do: "The user is blocked."
  defp session_refusal(:unconfirmed), do: "The user's email is not confirmed."
  defp session_refusal(:referral_required), do: "The user has not entered a referral code."

  defp find_tool(%{name: name} = state) when not is_binary(name),
    do: {:error, :not_found, "Unknown tool.", %{}, state}

  defp find_tool(%{audience: audience, name: name, resolve_name: resolve_name} = state) do
    name = if is_function(resolve_name, 1), do: resolve_name.(name), else: name

    case Registry.find(name, audience) do
      {:ok, %Tool{} = tool} ->
        {:ok, %{state | tool: with_client_token(tool)}}

      {:error, :not_found} ->
        clipped = clip(name)
        {:error, :not_found, "Unknown tool #{inspect(clipped)}.", %{tool: clipped}, state}

      {:error, :module_disabled} ->
        clipped = clip(name)

        {:error, :module_disabled, "The module that provides #{clipped} is disabled.",
         %{tool: clipped}, state}
    end
  end

  # The effective scopes are already on the actor and are not computed again. For a
  # `:key`, `Keys.verify/2` filtered the key's scopes by its owner's permissions for this
  # very request (never cached: blocking the owner or removing a role takes effect on the
  # next call). For a `:user`, `session_actor/1` took `Keys.held_scopes_of/1` of the
  # session's scope on this call.
  defp take_scopes(%{actor: %Actor{kind: kind, scopes: scopes}} = state)
       when kind in [:key, :user],
       do: {:ok, %{state | scopes: scopes}}

  defp take_scopes(state), do: {:ok, state}

  defp check_scope(%{tool: %Tool{scope: nil}} = state), do: {:ok, state}

  defp check_scope(%{tool: %Tool{scope: scope}, scopes: scopes} = state) do
    if scope in scopes do
      {:ok, state}
    else
      {:error, :forbidden, "#{holder(state)} lacks #{scope}.", %{required_scope: scope}, state}
    end
  end

  defp holder(%{actor: %Actor{kind: :user}}), do: "This session"
  defp holder(_state), do: "This key"

  # A session's own check of the tool's permission, besides the scope: the scope rule
  # already demands every permission behind a scope, this keeps the tool called by name
  # to its own. A tool without a permission (`system.*`) describes the calling key and is
  # not for a session.
  defp check_permission(%{actor: %Actor{scope: scope}, tool: %Tool{} = tool} = state) do
    if session_may_hold?(scope, tool) do
      {:ok, state}
    else
      {:error, :forbidden, "This session may not call #{tool.name}.", %{tool: tool.name}, state}
    end
  end

  defp session_may_hold?(scope, %Tool{scope: tool_scope, permission: permission})
       when is_binary(tool_scope) and is_binary(permission),
       do: Scope.can?(scope, permission)

  defp session_may_hold?(_scope, _tool), do: false

  defp session_may_call?(scope, %Tool{} = tool),
    do: not write?(tool) and session_may_hold?(scope, tool)

  # `allow: :read`: a write tool is refused here, before validation and `Flow.gate/1`.
  defp reads_only(%{tool: %Tool{} = tool} = state) do
    if write?(tool) do
      {:error, :forbidden, "#{tool.name} writes; this call allows reads only.",
       %{tool: tool.name}, state}
    else
      {:ok, state}
    end
  end

  # `Registry.find/2` costs about 2 ms on a miss (it asks the switched-off
  # modules), so the public audience, whose callers need no key, is charged
  # BEFORE the lookup: a flood of unknown tool names ends in 429 without the
  # lookup. What it pays there is 1 unit of the network bucket only: the client
  # token is not known before the tool is. The admin audience is charged after
  # the lookup, because its price depends on the tool and its caller is
  # authenticated.
  defp charge_before_lookup(%{audience: :public} = state), do: rate_limit(state)
  defp charge_before_lookup(state), do: {:ok, state}

  defp charge_after_lookup(%{audience: :admin} = state), do: rate_limit(state)

  # The public audience paid 1 unit of the network bucket before the lookup. Now the
  # tool and its client token are known: the token's bucket is charged the full price and
  # the network's the rest. A call with no token and a price of 1 has nothing left to pay.
  defp charge_after_lookup(
         %{audience: :public, tool: %Tool{} = tool, input: input, actor: actor} = state
       ) do
    case {actor.client_token_hash, cost(tool, input)} do
      {nil, 1} ->
        {:ok, state}

      {hash, cost} ->
        (actor.ip || "unknown")
        |> RateLimit.check_public(hash, cost, cost - 1)
        |> limited(state)
    end
  end

  defp rate_limit(%{audience: :admin, actor: %Actor{kind: :user, user_uuid: user_uuid}} = state) do
    user_uuid
    |> RateLimit.check_user(cost(state.tool, state.input))
    |> limited(state)
  end

  defp rate_limit(%{audience: :admin, actor: actor} = state) do
    actor.key_uuid
    |> RateLimit.check_admin(cost(state.tool, state.input))
    |> limited(state)
  end

  # Before the lookup, and for the list of tools: the network bucket, 1 unit.
  defp rate_limit(%{audience: :public, actor: actor} = state) do
    (actor.ip || "unknown")
    |> RateLimit.check_public(nil, 1)
    |> limited(state)
  end

  defp limited({:ok, headers}, state),
    do: {:ok, %{state | headers: headers, charged?: true}}

  defp limited({:error, retry_after, headers}, state) do
    {:error, :rate_limited, "Too many requests.", %{retry_after: retry_after},
     %{state | headers: headers}}
  end

  defp validate(%{tool: tool, input: input} = state) when is_map(input) do
    case validate_input(tool, input) do
      {:ok, valid} -> {:ok, %{state | input: valid}}
      {:error, errors} -> invalid(state, errors)
    end
  end

  defp validate(state) do
    invalid(state, [%{path: "", message: "must be a JSON object", limit: nil, allowed: nil}])
  end

  # Every root schema is closed here: an unknown top-level field is a
  # validation error. A write tool also gets the control fields
  # (`PhoenixKit.API.ControlFields`).
  @doc """
  The input schema the executor enforces for `tool`: the tool's own schema,
  closed at the root with `additionalProperties: false`, with string keys, and for a write
  tool with the control fields (`dry_run`, `confirm_token`, `idempotency_key`).
  MCP's `inputSchema` and OpenAPI's request body are built from it, so a client
  is told exactly what the validator will accept.
  Nested objects retain the module's policy; declare `additionalProperties: false`
  on each nested object that must reject unknown fields.
  """
  @spec input_schema(Tool.t()) :: map()
  def input_schema(%Tool{input_schema: schema} = tool),
    do: Validator.close_schema(schema || @empty_schema, ControlFields.properties(tool))

  defp invalid(state, errors) do
    {:error, :validation_failed, "The input does not match the schema of #{state.tool.name}.",
     %{errors: errors}, state}
  end

  @doc false
  # The `max_items` check and the closed-schema validation of a request, as one function.
  # `validate/1` calls it; an approval calls it again at decision time.
  @spec validate_input(Tool.t(), map()) :: {:ok, map()} | {:error, [map()]}
  def validate_input(%Tool{} = tool, input) when is_map(input) do
    with :ok <- check_max_items(tool, input) do
      Validator.validate(input_schema(tool), input)
    end
  end

  @doc false
  # The tool lookup and scope check of a request (`find_tool/1`, `check_scope/1`), for code
  # that has no request: `{:ok, tool}` or the code, detail and context of the refusal.
  @spec authorize_tool(String.t(), :admin | :public, [String.t()]) ::
          {:ok, Tool.t()} | {:error, atom(), String.t(), map()}
  def authorize_tool(name, audience, scopes) when is_binary(name) do
    state = %{audience: audience, name: name, resolve_name: nil, scopes: scopes, tool: nil}

    with {:ok, state} <- find_tool(state),
         {:ok, state} <- check_scope(state) do
      {:ok, state.tool}
    else
      {:error, code, detail, context, _state} -> {:error, code, detail, context}
    end
  end

  @doc false
  # The one definition of the handler context's shape. Every key is always present; a
  # field that is not given gets its safe default; a field that is not a context key is
  # dropped. A request and an approved operation both build their context here.
  @spec context_from(map()) :: map()
  def context_from(%{} = fields) do
    actor = Map.get(fields, :actor)

    %{
      actor: actor,
      scopes: Map.get(fields, :scopes) || (actor && actor.scopes) || [],
      scope: Map.get(fields, :scope) || actor_scope(actor),
      audience: Map.get(fields, :audience) || :admin,
      language: Map.get(fields, :language),
      currency: Map.get(fields, :currency),
      hosts: Map.get(fields, :hosts) || [],
      base_url: Map.get(fields, :base_url),
      request_id: Map.get(fields, :request_id),
      dry_run?: Map.get(fields, :dry_run?) == true,
      approved_by_uuid: Map.get(fields, :approved_by_uuid),
      confirmation_uuid: Map.get(fields, :confirmation_uuid),
      progress: Map.get(fields, :progress) || fn _partial -> :ok end
    }
  end

  defp actor_scope(%Actor{scope: scope}), do: scope
  defp actor_scope(_actor), do: nil

  @doc false
  @spec context_keys() :: [atom()]
  def context_keys, do: %{} |> context_from() |> Map.keys()

  defp check_max_items(%Tool{max_items: max}, input) when is_integer(max) do
    case largest_list(input) do
      {field, count} when count > max ->
        {:error,
         [
           %{
             path: field,
             message: "must have at most #{max} items",
             limit: max,
             allowed: nil
           }
         ]}

      _within_limit ->
        :ok
    end
  end

  defp check_max_items(_tool, _input), do: :ok

  # A dry run: the handler answers a preview and writes nothing.
  defp run(%{dry_run?: true} = state), do: run_preview(state)

  # The handler runs under a rescue: whatever it does, the client gets a
  # problem document and the key keeps working. What the log learns, never the
  # values the handler worked on:
  #
  #   * a bad result: its shape (`LogSafe.shape/1`);
  #   * a throw or an exit: the kind and the shape of the reason;
  #   * an exception: its module always, its message only for the exceptions
  #     with a fixed message (`ArithmeticError`, `FunctionClauseError`; see
  #     `LogSafe`), and the stacktrace with the frames' arguments replaced by
  #     their count (`exception_report/2`).
  defp run(%{tool: %Tool{handler: {module, function}}, input: input} = state) do
    case apply(module, function, [input, build_ctx(state)]) do
      {:ok, result} when is_map(result) ->
        {:ok, %{state | body: encode(result), result: result}}

      {:ok, result, effects} when is_map(result) and is_list(effects) ->
        result = Map.put(result, "effects", effects)
        {:ok, %{state | body: encode(result), result: result}}

      {:error, code, message, context}
      when is_atom(code) and is_binary(message) and is_map(context) ->
        error_result(state, code, message, context)

      other ->
        crashed(state, "returned #{LogSafe.shape(other)}")
    end
  rescue
    error -> crashed(state, exception_report(error, __STACKTRACE__))
  catch
    kind, reason -> crashed(state, "#{kind}: #{LogSafe.shape(reason)}")
  end

  # A message that is not valid UTF-8 cannot be encoded as JSON; it is a broken
  # handler like any other bad result.
  defp error_result(state, code, message, context) do
    if String.valid?(message),
      do: {:error, code, message, context, state},
      else: crashed(state, "returned an error whose message is not valid UTF-8")
  end

  # What the log learns about an exception: `LogSafe.exception_label/1` (its
  # module, its message only for the fixed-message kinds) and the stacktrace with the
  # frames' argument values replaced by their count (a `FunctionClauseError`
  # frame carries the arguments) and without the frame of an undefined call.
  @doc false
  def exception_report(error, stacktrace) do
    frames = stacktrace |> without_undefined_call(error) |> Enum.map(&without_arguments/1)
    LogSafe.exception_label(error) <> "\n" <> Exception.format_stacktrace(frames)
  end

  # The frame of an undefined call names the module the code tried to call,
  # and a handler can build that name from a request value
  # (`Module.concat([value])`). The frame below it still names the handler and
  # the line.
  defp without_undefined_call(
         [{module, function, _arguments, _location} | rest],
         %UndefinedFunctionError{module: module, function: function}
       ),
       do: rest

  defp without_undefined_call(stacktrace, _error), do: stacktrace

  # A stacktrace frame with its arguments replaced by their count: the
  # `{module, function, arguments, location}` of a call and the
  # `{fun, arguments, location}` of an anonymous function. Public only for
  # its test: the second form does not occur in a stacktrace the BEAM builds
  # today.
  @doc false
  def without_arguments({module, function, arguments, location}) when is_list(arguments),
    do: {module, function, length(arguments), location}

  def without_arguments({fun, arguments, location}) when is_list(arguments),
    do: {fun, length(arguments), location}

  def without_arguments(frame), do: frame

  defp crashed(state, what) do
    Logger.error(
      "[PhoenixKit.API] tool #{state.tool.name} failed (request #{request_id(state)}): #{what}"
    )

    {:error, :internal_error, "The tool failed unexpectedly.", %{}, state}
  end

  # --- outcomes -------------------------------------------------------------

  # A request that ended with an answer: the handler's, or one a `Flow` step
  # ended (a preview, a confirmation prompt, a replay). The audit entry is
  # written here and the idempotency claim is finished; the answer of a replay
  # carries the `idempotent-replayed` header, and so does the held answer of a
  # call that an approval already waits for (`held_again?`).
  defp complete(%{body: body, result: result} = state) do
    log_write(state, state.outcome || "ok", nil)
    Flow.finish(state)

    {:ok, %{result: result, json: body}, replay_headers(state)}
  end

  # The limiter's own refusal has already been charged; it is answered as it
  # stands, not charged again.
  defp refused(state, :rate_limited, detail, context),
    do: failed(state, :rate_limited, detail, context)

  # An admin call the lookup or the scope check refused never met the limiter
  # (`charged?` is still false and the caller is a key or a live session; nothing
  # else can end an admin request there). It pays one unit, as a `ping` does, so
  # unknown names are not free; an empty budget turns the refusal into `429`.
  # `charged?` stays false: a refusal writes no audit entry. A session that could
  # not act at all (gone, blocked) has no actor and pays nothing.
  defp refused(
         %{audience: :admin, charged?: false, actor: %Actor{kind: :key, key_uuid: key_uuid}} =
           state,
         code,
         detail,
         context
       ),
       do: key_uuid |> RateLimit.check_admin(1) |> refusal_charged(state, code, detail, context)

  defp refused(
         %{audience: :admin, charged?: false, actor: %Actor{kind: :user, user_uuid: user_uuid}} =
           state,
         code,
         detail,
         context
       ),
       do: user_uuid |> RateLimit.check_user(1) |> refusal_charged(state, code, detail, context)

  defp refused(state, code, detail, context), do: failed(state, code, detail, context)

  defp refusal_charged(charge, state, code, detail, context) do
    case charge do
      {:ok, headers} ->
        failed(%{state | headers: headers}, code, detail, context)

      {:error, retry_after, headers} ->
        failed(
          %{state | headers: headers},
          :rate_limited,
          "Too many requests.",
          %{retry_after: retry_after}
        )
    end
  end

  # A refused or failed request releases its idempotency claim, so the same
  # key can be retried.
  defp failed(state, code, detail, context) do
    Flow.release(state)
    log_write(state, "error", code)

    {:error, code, detail, context, state.headers}
  end

  defp replay_headers(%{replayed?: true, headers: headers}),
    do: headers ++ [{"idempotent-replayed", "true"}]

  defp replay_headers(%{held_again?: true, headers: headers}),
    do: headers ++ [{"idempotent-replayed", "true"}]

  defp replay_headers(%{headers: headers}), do: headers

  # --- responses ------------------------------------------------------------

  defp send_json(conn, headers, body) do
    conn
    |> put_headers(headers)
    |> put_resp_header("content-type", "application/json; charset=utf-8")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(200, body)
  end

  defp send_problem(conn, headers, code, detail, context) do
    conn
    |> put_headers(headers)
    |> Problem.send(code, detail, context)
  end

  defp put_headers(conn, headers) do
    Enum.reduce(headers, conn, fn {name, value}, acc ->
      put_resp_header(acc, String.downcase(name), to_string(value))
    end)
  end

  defp encode(map), do: JSON.encode!(map)

  # --- the audit entry ------------------------------------------------------

  # Only calls that were charged (`charged?` is set once rights and rate limit
  # have passed; for the public audience the charge comes before the lookup,
  # so the tool may still be unknown), and only for a key: an anonymous public
  # write belongs to the module that owns it and must not fill the activity
  # table.
  defp audit?(%{replayed?: true}), do: false

  defp audit?(%{charged?: true, tool: %Tool{} = tool, actor: %Actor{kind: :key}}),
    do: write?(tool)

  defp audit?(_state), do: false

  defp write?(%Tool{} = tool), do: ControlFields.write_tool?(tool)

  defp log_write(%{tool: tool, actor: actor} = state, outcome, code) do
    if audit?(state), do: write_entry(state, tool, actor, outcome, code)

    :ok
  end

  defp write_entry(state, tool, actor, outcome, code) do
    Activity.log("api", "api.request",
      actor_uuid: actor.user_uuid,
      mode: "auto",
      resource_type: "api_key",
      resource_uuid: actor.key_uuid,
      metadata: %{
        "via" => "api",
        "tool" => tool.name,
        "key_prefix" => actor.key_prefix,
        "request_id" => request_id(state),
        "rows" => state.rows,
        "outcome" => outcome,
        "code" => code && Atom.to_string(code)
      }
    )
  end

  # --- helpers --------------------------------------------------------------

  # The host's `:api_request_context` hook is host code (in a multi-domain install, maybe a
  # database read), and a dangerous call builds its handler context up to three times: ask once.
  defp resolve_request_context(state),
    do: {:ok, %{state | request_context: RequestContext.resolve(state.conn)}}

  defp build_ctx(state) do
    context = Map.get(state, :request_context) || RequestContext.resolve(state.conn)

    context_from(%{
      actor: state.actor,
      scopes: state.scopes,
      audience: state.audience,
      language: context.language,
      currency: context.currency,
      hosts: context.hosts,
      base_url: context.base_url,
      request_id: request_id(state),
      dry_run?: state.dry_run?,
      confirmation_uuid: state.confirmation && state.confirmation.uuid
    })
  end

  defp request_id(%{conn: %Plug.Conn{} = conn}), do: conn.assigns[:phoenix_kit_api_request_id]
  defp request_id(state), do: Map.get(state, :request_id)

  defp visible_scopes(%{audience: :admin, scopes: scopes}), do: scopes
  defp visible_scopes(%{audience: :public}), do: :all

  defp describe(%Tool{} = tool) do
    %{
      "name" => tool.name,
      "title" => tool.title,
      "description" => tool.description,
      "scope" => tool.scope,
      "input_schema" => input_schema(tool),
      "output_schema" => OutputShape.for_tool(tool),
      "annotations" => tool.annotations
    }
  end

  @doc """
  Rate-limit units one call of `tool` with `input` costs (the cost
  is clamped).

  1 for everything, except a tool of the admin audience that is not
  read-only: it costs `max(1, ceil(rows / 50))`, where `rows` is the length
  of the longest top-level list in the input, clamped:

    * a tool with `max_items`: `rows` counts up to `max_items` at most, so
      the price is at most `ceil(max_items / 50)`. A list above `max_items`
      is refused with 422, and a refused request must not use up the key's
      budget, so it is charged as a full batch, not as its real size;
    * a tool without `max_items`: `rows` counts up to 1000 at most, so the
      price is at most 20 units, for the same reason (the 2 MB limit of
      `PhoenixKit.API.BodyGuard` bounds the work of such a request).

  So an admin read with a long `fields` list costs 1, a public call with a
  50-line list costs 1 and an admin write of 120 rows costs 3. `nil` (the
  discovery list) and an input that is not a map cost 1.

  A tool that declares `cost:` (`PhoenixKit.API.Tool`) is priced by it
  instead.
  """
  @spec cost(Tool.t() | nil, term()) :: pos_integer()
  def cost(%Tool{cost: declared} = tool, input) when not is_nil(declared) do
    case declared_cost(declared, input) do
      {:ok, units} -> units
      :error -> default_cost(tool, input)
    end
  end

  def cost(tool, input), do: default_cost(tool, input)

  @max_cost 1000

  # The price a tool declares. A function is called with the raw input; one
  # that raises, throws or answers with anything but a positive integer is the
  # tool author's bug, so it is logged and the default rule applies instead of
  # the call being refused. Only the kind of the failure is logged, never a
  # value derived from the request.
  defp declared_cost(units, _input) when is_integer(units) and units > 0,
    do: {:ok, min(units, @max_cost)}

  defp declared_cost({module, function}, input) when is_atom(module) and is_atom(function) do
    case apply(module, function, [input]) do
      units when is_integer(units) and units > 0 ->
        {:ok, min(units, @max_cost)}

      other ->
        bad_cost(module, function, "returned #{LogSafe.shape(other)}")
    end
  rescue
    error -> bad_cost(module, function, "raised #{LogSafe.exception_label(error)}")
  catch
    kind, reason -> bad_cost(module, function, "#{kind}: #{LogSafe.shape(reason)}")
  end

  defp declared_cost(_other, _input), do: :error

  defp bad_cost(module, function, what) do
    Logger.warning(
      "[PhoenixKit.API] cost function #{inspect(module)}.#{function}/1 #{what}; using the default cost rule"
    )

    :error
  end

  defp default_cost(%Tool{audience: :admin} = tool, input) when is_map(input) do
    if write?(tool), do: max(1, ceil(billable_rows(tool, input) / @rows_per_unit)), else: 1
  end

  defp default_cost(_tool, _input), do: 1

  # A list longer than the tool's `max_items` is refused with 422 anyway, so it
  # is charged as a list of `max_items` rows: one oversized request cannot use
  # up the key's budget and turn its next valid call into a 429. A tool with
  # no `max_items` is capped at `@default_max_billable_rows` for the same
  # reason.
  defp billable_rows(%Tool{max_items: max}, input) when is_integer(max),
    do: min(rows(input), max)

  defp billable_rows(_tool, input), do: min(rows(input), @default_max_billable_rows)

  # Rows a call touches: the length of the longest list in the input, and 1
  # for an input without a list.
  defp rows(input) when is_map(input) do
    case largest_list(input) do
      {_field, count} -> max(count, 1)
      nil -> 1
    end
  end

  defp rows(_input), do: 1

  defp largest_list(input) do
    input
    |> Enum.flat_map(fn
      {field, value} when is_binary(field) and is_list(value) -> [{field, length(value)}]
      _other -> []
    end)
    |> Enum.max_by(&elem(&1, 1), fn -> nil end)
  end

  @doc false
  # Runs the handler as a dry run (used by `PhoenixKit.API.Flow`): `{:ok, state}` with
  # `state.preview` set to `%{data: map, fingerprint: binary}`, or the usual error tuple.
  @spec preview(map()) :: {:ok, map()} | {:error, atom(), String.t(), map(), map()}
  def preview(state), do: run(%{state | dry_run?: true})

  @doc false
  # The handler context of this request, with `overrides` merged over it.
  @spec context(map(), keyword()) :: map()
  def context(state, overrides \\ []),
    do: state |> build_ctx() |> Map.merge(Map.new(overrides)) |> context_from()

  defp run_preview(%{tool: %Tool{handler: {module, function}}, input: input} = state) do
    case apply(module, function, [input, build_ctx(state)]) do
      {:preview, preview, fingerprint} when is_map(preview) and is_binary(fingerprint) ->
        preview_result(state, preview, fingerprint)

      {:error, code, message, context}
      when is_atom(code) and is_binary(message) and is_map(context) ->
        error_result(state, code, message, context)

      other ->
        crashed(
          state,
          "answered a dry run with #{LogSafe.shape(other)} " <>
            "(a tool must answer a dry run with {:preview, preview, fingerprint} and write nothing)"
        )
    end
  rescue
    error -> crashed(state, exception_report(error, __STACKTRACE__))
  catch
    kind, reason -> crashed(state, "#{kind}: #{LogSafe.shape(reason)}")
  end

  # The fingerprint is kept in a confirmation code or an approval, so one the row cannot hold
  # is a failed handler here, not an exception (or a refused row) further on.
  defp preview_result(state, preview, fingerprint) do
    if Confirmation.fingerprint_valid?(fingerprint) do
      {:ok, %{state | preview: %{data: json_safe!(preview), fingerprint: fingerprint}}}
    else
      crashed(
        state,
        "answered a dry run with a fingerprint the store cannot hold " <>
          "(#{byte_size(fingerprint)} bytes; it must be 1 to #{Confirmation.fingerprint_max()} bytes of UTF-8)"
      )
    end
  end

  # The preview as the client will read it: encoded and decoded again under the rescue of
  # `run_preview/1`, so a value JSON cannot hold (a tuple, a struct without an encoder, a
  # binary that is not UTF-8) is a failed handler, not an exception out of `execute/4`.
  defp json_safe!(preview), do: preview |> JSON.encode!() |> JSON.decode!()

  # The first `@clip_codepoints` code points, not graphemes: a single grapheme
  # can carry any number of combining marks. The work is bounded by the output,
  # not by the name: the client chooses how long the name is.
  defp clip(name), do: LogSafe.take_codepoints(name, @clip_codepoints)
end
