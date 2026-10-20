defmodule PhoenixKit.API.Actor do
  @moduledoc """
  Who is calling the API: a key (with its owner and effective scopes), a person's live
  browser session (in process, `PhoenixKit.API.Executor.execute_as/5`) or an anonymous
  public caller.

    * `kind` - `:key` for a verified bearer key, `:user` for a live session,
      `:anonymous` for a public caller.
    * `key_uuid`, `key_prefix` - the key, when there is one (`nil` for `:user`).
    * `user_uuid` - the key's owner, or the session's user.
    * `scopes` - the key's effective scopes (its own, filtered by the owner's live
      permissions), or the scopes the session's scope holds
      (`PhoenixKit.API.Keys.held_scopes_of/1`).
    * `scope` - the `PhoenixKit.Users.Auth.Scope` those scopes were computed from: the
      owner's `Scope.for_user(owner, narrow: false)` for a key, the session's narrowed
      scope for `:user`, `nil` for an anonymous caller. Handlers read it as `ctx.scope`.
    * `requires_approval` - the key's dangerous operations wait for a human.
    * `cart_token_hash` - the hashed cart token of an anonymous public caller.
    * `ip` - the address the request came from, as a string.

  The default is the least-privileged value: anonymous, no scopes, no approval.

  `inspect/1` leaves `scope` out: it holds the user (email, name), and the actor sits in
  `conn.assigns` on every API request, where error reports and debug pages print it.
  """

  @derive {Inspect, except: [:scope]}
  defstruct kind: :anonymous,
            key_uuid: nil,
            key_prefix: nil,
            user_uuid: nil,
            scopes: [],
            scope: nil,
            requires_approval: false,
            cart_token_hash: nil,
            ip: nil

  @type t :: %__MODULE__{
          kind: :key | :user | :anonymous,
          key_uuid: String.t() | nil,
          key_prefix: String.t() | nil,
          user_uuid: String.t() | nil,
          scopes: [String.t()],
          scope: PhoenixKit.Users.Auth.Scope.t() | nil,
          requires_approval: boolean(),
          cart_token_hash: String.t() | nil,
          ip: String.t() | nil
        }
end
