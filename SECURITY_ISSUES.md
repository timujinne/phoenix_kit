# PhoenixKit Authentication Security Issues

This file contains GitHub issues templates for security vulnerabilities found during the security audit.

---

## 🚨 CRITICAL PRIORITY ISSUES

### Issue #1: Add Rate Limiting to Authentication Endpoints

**Priority:** 🔴 Critical
**Labels:** `security`, `critical`, `authentication`

**Description:**
The authentication system lacks rate limiting protection, making it vulnerable to brute-force attacks on multiple endpoints.

**Affected Components:**
- Login endpoint (`get_user_by_email_and_password`)
- Magic Link generation (`generate_magic_link`)
- Password reset requests (`deliver_user_reset_password_instructions`)
- Email confirmation requests

**Security Impact:**
- ❌ Brute-force password attacks
- ❌ Email enumeration attacks
- ❌ Token brute-forcing
- ❌ Account takeover via mass attempts

**Proposed Solution:**
Integrate rate limiting library (Hammer or ExRated):

```elixir
# Add to mix.exs
{:hammer, "~> 6.1"}

# Add to Auth module
defp check_rate_limit(identifier, action, window_ms \\ 60_000, max_attempts \\ 5) do
  case Hammer.check_rate("auth:#{action}:#{identifier}", window_ms, max_attempts) do
    {:allow, _count} -> :ok
    {:deny, _limit} -> {:error, :rate_limit_exceeded}
  end
end

# Usage in get_user_by_email_and_password:
def get_user_by_email_and_password(email, password) do
  with :ok <- check_rate_limit(email, "login"),
       user when not is_nil(user) <- Repo.get_by(User, email: email),
       true <- User.valid_password?(user, password) do
    user
  else
    {:error, :rate_limit_exceeded} -> nil
    _ ->
      # Record failed attempt
      Bcrypt.no_user_verify()
      nil
  end
end
```

**Rate Limits Recommendations:**
- Login: 5 attempts per 15 minutes per email
- Magic Link: 3 requests per 15 minutes per email
- Password Reset: 3 requests per 15 minutes per email
- Global IP limit: 20 requests per minute

**Files to Modify:**
- `lib/phoenix_kit/users/auth.ex`
- `lib/phoenix_kit/users/magic_link.ex`
- `mix.exs` (add dependency)

---

### Issue #2: Fix Timing Attack in Magic Link Authentication

**Priority:** 🔴 Critical
**Labels:** `security`, `critical`, `timing-attack`

**Description:**
The magic link generation has a timing attack vulnerability that allows attackers to determine if an email exists in the system.

**Affected File:** `lib/phoenix_kit/users/magic_link.ex:101-105`

**Current Code (Vulnerable):**
```elixir
nil ->
  # Perform a fake token generation to prevent timing attacks
  _fake_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  {:error, :user_not_found}
```

**Problem:**
The fake token generation doesn't include:
- Database query simulation
- Password hashing simulation
- Consistent timing across both branches

Attackers can use timing analysis to enumerate valid email addresses.

**Proposed Solution:**
```elixir
nil ->
  # Simulate database query timing to prevent timing attacks
  # Use a small sleep to match average DB query time
  Process.sleep(1)  # 1ms average query time

  # Simulate bcrypt timing (if used elsewhere in auth flow)
  Bcrypt.no_user_verify()

  {:error, :user_not_found}
```

**Alternative Solution (More Robust):**
```elixir
def generate_magic_link(email) when is_binary(email) do
  email = String.trim(email) |> String.downcase()

  # Always perform these operations regardless of user existence
  {token, hashed_token} = generate_token_pair()

  case Auth.get_user_by_email(email) do
    %User{} = user ->
      # Revoke existing magic links
      revoke_magic_links(user)

      # Insert new token
      user_token = %UserToken{
        token: hashed_token,
        context: @magic_link_context,
        sent_to: email,
        user_id: user.id
      }

      case repo().insert(user_token) do
        {:ok, _} -> {:ok, user, token}
        {:error, changeset} -> {:error, changeset}
      end

    nil ->
      # Simulate the same operations with fake data
      _fake_revoke = simulate_revoke_operation()
      _fake_insert = simulate_insert_operation()

      {:error, :user_not_found}
  end
end

defp simulate_revoke_operation do
  # Simulate delete_all timing
  Process.sleep(1)
end

defp simulate_insert_operation do
  # Simulate insert timing
  Process.sleep(2)
end
```

**Testing:**
Add timing attack tests to verify consistent response times:

```elixir
test "magic link generation has consistent timing for existing and non-existing emails" do
  existing_email = "user@example.com"
  fake_email = "nonexistent@example.com"

  # Create user
  {:ok, _user} = create_user(%{email: existing_email})

  # Measure timing for existing email
  {time1, _} = :timer.tc(fn ->
    MagicLink.generate_magic_link(existing_email)
  end)

  # Measure timing for non-existing email
  {time2, _} = :timer.tc(fn ->
    MagicLink.generate_magic_link(fake_email)
  end)

  # Times should be within 10% of each other
  diff_percentage = abs(time1 - time2) / max(time1, time2) * 100
  assert diff_percentage < 10, "Timing difference too large: #{diff_percentage}%"
end
```

**Files to Modify:**
- `lib/phoenix_kit/users/magic_link.ex`
- `test/phoenix_kit/users/magic_link_test.exs`

---

### Issue #3: Reduce Password Reset Token Expiry Time

**Priority:** 🔴 Critical
**Labels:** `security`, `critical`, `tokens`

**Description:**
Password reset tokens are valid for 24 hours, which is too long and increases the risk of account takeover if an email account is compromised.

**Affected File:** `lib/phoenix_kit/users/auth/user_token.ex:31`

**Current Code:**
```elixir
@reset_password_validity_in_days 1  # 24 hours
```

**Security Impact:**
If an attacker gains temporary access to a user's email (e.g., through XSS, session hijacking, or public computer), they have 24 hours to use the password reset link.

**Industry Standards:**
- OWASP: 15-60 minutes
- NIST: 1 hour maximum
- Most secure systems: 15-30 minutes

**Proposed Solution:**
```elixir
# Change to hours-based expiry
@reset_password_validity_in_hours 1  # 1 hour maximum

# Update verification function
defp days_for_context("reset_password"), do: @reset_password_validity_in_hours

# Update query to use hours
def verify_email_token_query(token, "reset_password" = context) do
  case Base.url_decode64(token, padding: false) do
    {:ok, decoded_token} ->
      hashed_token = :crypto.hash(@hash_algorithm, decoded_token)
      hours = @reset_password_validity_in_hours

      query =
        from token in by_token_and_context_query(hashed_token, context),
          join: user in assoc(token, :user),
          where: token.inserted_at > ago(^hours, "hour"),  # Changed to hours
          where: token.sent_to == user.email,
          select: user

      {:ok, query}
    :error ->
      :error
  end
end
```

**Alternative: Configurable Expiry**
```elixir
# config/config.exs
config :phoenix_kit, :token_expiry,
  reset_password_hours: 1,
  confirm_email_days: 7,
  magic_link_minutes: 15

# In UserToken module
defp reset_password_expiry do
  Application.get_env(:phoenix_kit, :token_expiry, [])
  |> Keyword.get(:reset_password_hours, 1)
end
```

**Migration Considerations:**
- Existing tokens with old expiry will still work until they expire
- No database migration needed (expiry is calculated at verification time)
- Update user-facing documentation about token expiry

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user_token.ex`
- Documentation/README files mentioning token expiry

---

### Issue #4: Increase Magic Link Token Size

**Priority:** 🟠 High
**Labels:** `security`, `high`, `tokens`, `cryptography`

**Description:**
Magic link tokens use 32 bytes of random data, which may be insufficient for passwordless authentication in high-volume systems.

**Affected File:** `lib/phoenix_kit/users/auth/user_token.ex:27`

**Current Code:**
```elixir
@rand_size 32  # 32 bytes = ~43 chars after base64
```

**Security Analysis:**
- **Current entropy:** 32 bytes = 256 bits
- **After Base64:** ~43 characters
- **Security level:** Good for most applications, but can be improved

**Risk Assessment:**
For passwordless authentication (magic links), the token serves as the ONLY authentication factor, making it more critical than session tokens that are paired with passwords.

**Industry Standards:**
- Session tokens: 32 bytes (256 bits) - sufficient
- API keys: 32 bytes (256 bits) - sufficient
- Passwordless auth tokens: 48-64 bytes (384-512 bits) - recommended

**Proposed Solution:**
```elixir
# Increase to 48 bytes for better security margin
@rand_size 48  # 48 bytes = ~64 chars after base64 = 384 bits entropy

# Or make it configurable per context
@session_token_size 32
@magic_link_token_size 48
@email_token_size 32

def build_session_token(user) do
  token = :crypto.strong_rand_bytes(@session_token_size)
  {token, %UserToken{token: token, context: "session", user_id: user.id}}
end

def build_magic_link_token(user) do
  token = :crypto.strong_rand_bytes(@magic_link_token_size)
  hashed_token = :crypto.hash(@hash_algorithm, token)

  {Base.url_encode64(token, padding: false),
   %UserToken{
     token: hashed_token,
     context: "magic_link",
     sent_to: user.email,
     user_id: user.id
   }}
end
```

**Benefits:**
- ✅ Increased security margin against brute-force
- ✅ Future-proof against advances in computing power
- ✅ Aligns with industry best practices for passwordless auth

**Performance Impact:**
- Minimal: generating 48 vs 32 bytes is negligible
- URL length increases by ~21 characters (acceptable)

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user_token.ex`
- `lib/phoenix_kit/users/magic_link.ex` (if separate token generation)

---

## ⚠️ HIGH PRIORITY ISSUES

### Issue #5: Enforce Email Confirmation Before Authentication

**Priority:** 🟠 High
**Labels:** `security`, `high`, `authentication`, `email-verification`

**Description:**
Users can authenticate and access the application without confirming their email address. This poses multiple security risks.

**Affected Files:**
- `lib/phoenix_kit_web/users/auth.ex:474-475`
- `lib/phoenix_kit_web/users/auth.ex:495-496`

**Current Code:**
```elixir
def require_authenticated_user(conn, _opts) do
  if conn.assigns[:phoenix_kit_current_user] do
    conn  # ← No email confirmation check
  else
    # redirect to login
  end
end
```

**Security Risks:**
1. **Account Enumeration:** Attackers can create accounts with victim's email and check if login works
2. **Typo Squatting:** Users register with typos (user@gmial.com instead of user@gmail.com) and gain access
3. **Spam/Bot Accounts:** Automated accounts can function without valid email
4. **Data Integrity:** User data may be associated with invalid email addresses

**Proposed Solution:**

**Option 1: Hard Enforcement (Recommended)**
```elixir
def require_authenticated_user(conn, _opts) do
  case conn.assigns[:phoenix_kit_current_user] do
    %{confirmed_at: nil} = user ->
      conn
      |> put_flash(:error, "Please confirm your email before accessing the application.")
      |> redirect(to: Routes.path("/users/confirmation-pending"))
      |> halt()

    %{confirmed_at: _} = user ->
      conn

    nil ->
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> maybe_store_return_to()
      |> redirect(to: Routes.path("/users/log-in"))
      |> halt()
  end
end
```

**Option 2: Configurable Enforcement**
```elixir
# config/config.exs
config :phoenix_kit, :authentication,
  require_email_confirmation: true,
  grace_period_hours: 24  # Allow 24h grace period

# In auth plug
def require_authenticated_user(conn, _opts) do
  if user = conn.assigns[:phoenix_kit_current_user] do
    if should_enforce_email_confirmation?() do
      check_email_confirmation(conn, user)
    else
      conn
    end
  else
    redirect_to_login(conn)
  end
end

defp should_enforce_email_confirmation? do
  Application.get_env(:phoenix_kit, :authentication, [])
  |> Keyword.get(:require_email_confirmation, true)
end

defp check_email_confirmation(conn, user) do
  cond do
    user.confirmed_at != nil ->
      conn

    within_grace_period?(user) ->
      conn
      |> put_flash(:info, "Please confirm your email. Check your inbox.")

    true ->
      conn
      |> put_flash(:error, "You must confirm your email to continue.")
      |> redirect(to: Routes.path("/users/confirmation-pending"))
      |> halt()
  end
end

defp within_grace_period?(user) do
  grace_hours = Application.get_env(:phoenix_kit, :authentication, [])
                |> Keyword.get(:grace_period_hours, 0)

  if grace_hours > 0 do
    cutoff = NaiveDateTime.add(user.inserted_at, grace_hours * 3600)
    NaiveDateTime.compare(NaiveDateTime.utc_now(), cutoff) == :lt
  else
    false
  end
end
```

**Additional Changes Needed:**

1. **Create Confirmation Pending Page:**
```elixir
# lib/phoenix_kit_web/live/confirmation_pending_live.ex
defmodule PhoenixKitWeb.ConfirmationPendingLive do
  use PhoenixKitWeb, :live_view

  def render(assigns) do
    ~H"""
    <div class="max-w-md mx-auto mt-8">
      <h1>Email Confirmation Required</h1>
      <p>Please check your email and click the confirmation link.</p>

      <button phx-click="resend_confirmation">
        Resend Confirmation Email
      </button>
    </div>
    """
  end

  def handle_event("resend_confirmation", _params, socket) do
    user = socket.assigns.phoenix_kit_current_user
    PhoenixKit.Users.Auth.deliver_user_confirmation_instructions(user)

    {:noreply, put_flash(socket, :info, "Confirmation email sent!")}
  end
end
```

2. **Update Magic Link to Auto-Confirm:**
```elixir
# In magic_link.ex
def verify_magic_link(token) do
  case repo().one(query) do
    {user, user_token} ->
      repo().delete(user_token)

      # Auto-confirm user on successful magic link auth
      user = if is_nil(user.confirmed_at) do
        {:ok, confirmed} = Auth.admin_confirm_user(user)
        confirmed
      else
        user
      end

      {:ok, user}
```

**Migration Strategy:**
1. Add configuration option (default: false for backward compatibility)
2. Add warning logs for unconfirmed user logins
3. After 1-2 releases, make it default: true
4. Eventually remove the option and always enforce

**Files to Modify:**
- `lib/phoenix_kit_web/users/auth.ex`
- `lib/phoenix_kit_web/live/confirmation_pending_live.ex` (new file)
- `lib/phoenix_kit_web/router.ex`
- `lib/phoenix_kit/users/magic_link.ex`
- `config/config.exs`

---

### Issue #6: Fix Username Generation Collisions

**Priority:** 🟠 High
**Labels:** `security`, `high`, `user-management`, `bug`

**Description:**
Username generation from email can create collisions when multiple users have similar email addresses, causing registration failures.

**Affected File:** `lib/phoenix_kit/users/auth/user.ex:399-460`

**Problem Example:**
```
john.doe@gmail.com  → username: john_doe
john.doe@yahoo.com  → username: john_doe  ← COLLISION!
john_doe@company.com → username: john_doe  ← COLLISION!
```

**Current Code:**
```elixir
defp maybe_generate_username_from_email(changeset) do
  username = get_change(changeset, :username)
  email = get_change(changeset, :email) || get_field(changeset, :email)

  case {username, email} do
    {nil, email} when is_binary(email) ->
      generated_username = generate_username_from_email(email)
      put_change(changeset, :username, generated_username)  # ← No uniqueness check!
    _ ->
      changeset
  end
end
```

**Security Impact:**
- 💥 Registration fails with cryptic database error
- 💥 Poor user experience
- 💥 Potential for username squatting/confusion

**Proposed Solution:**

```elixir
defp maybe_generate_username_from_email(changeset) do
  case get_change(changeset, :username) do
    nil ->
      email = get_change(changeset, :email) || get_field(changeset, :email)
      if email do
        generated_username = generate_unique_username_from_email(email)
        put_change(changeset, :username, generated_username)
      else
        changeset
      end
    _ ->
      changeset
  end
end

defp generate_unique_username_from_email(email) do
  base_username = generate_username_from_email(email)
  ensure_unique_username(base_username, 0)
end

defp ensure_unique_username(base_username, attempt) when attempt < 100 do
  username = case attempt do
    0 -> base_username
    n when n < 10 -> "#{base_username}_#{n}"
    n -> "#{base_username}_#{:crypto.strong_rand_bytes(3) |> Base.encode16(case: :lower)}"
  end

  repo = PhoenixKit.RepoHelper.repo()

  # Check if username exists
  if repo.get_by(User, username: username) do
    # Try next variant
    ensure_unique_username(base_username, attempt + 1)
  else
    username
  end
end

defp ensure_unique_username(_base_username, attempt) when attempt >= 100 do
  # Fallback to completely random username after 100 attempts
  "user_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
end
```

**Alternative: Add User ID Suffix**
```elixir
# After user is inserted, update username with ID suffix
def register_user(attrs) do
  case %User{}
       |> User.registration_changeset(attrs)
       |> Repo.insert() do
    {:ok, user} ->
      # If username was auto-generated, append user ID to ensure uniqueness
      if username_was_generated?(user, attrs) do
        update_username_with_id(user)
      else
        {:ok, user}
      end
    {:error, changeset} ->
      {:error, changeset}
  end
end

defp update_username_with_id(user) do
  new_username = "#{user.username}_#{user.id}"

  user
  |> Ecto.Changeset.change(username: new_username)
  |> Repo.update()
end
```

**Testing:**
```elixir
test "generates unique usernames for similar emails" do
  emails = [
    "john.doe@gmail.com",
    "john.doe@yahoo.com",
    "john_doe@company.com",
    "johndoe@example.com"
  ]

  users = Enum.map(emails, fn email ->
    {:ok, user} = Auth.register_user(%{
      email: email,
      password: "password123456"
    })
    user
  end)

  usernames = Enum.map(users, & &1.username)

  # All usernames should be unique
  assert length(Enum.uniq(usernames)) == length(usernames)

  # First user gets base username
  assert List.first(usernames) == "john_doe"

  # Subsequent users get suffixes
  assert Enum.all?(Enum.drop(usernames, 1), fn username ->
    String.starts_with?(username, "john_doe")
  end)
end
```

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user.ex`
- `lib/phoenix_kit/users/auth.ex` (if using post-insert approach)
- `test/phoenix_kit/users/auth/user_test.exs`

---

### Issue #7: Add Session Fingerprinting to Prevent Session Hijacking

**Priority:** 🟠 High
**Labels:** `security`, `high`, `session-management`, `authentication`

**Description:**
Session tokens can be used from any IP address and user agent, making them vulnerable to session hijacking attacks if stolen.

**Affected Files:**
- `lib/phoenix_kit_web/users/auth.ex:158-180`
- `lib/phoenix_kit/users/auth/user_token.ex`

**Current Behavior:**
```elixir
def fetch_phoenix_kit_current_user(conn, _opts) do
  {user_token, conn} = ensure_user_token(conn)
  user = user_token && Auth.get_user_by_session_token(user_token)
  # ← No verification of IP or User-Agent
  assign(conn, :phoenix_kit_current_user, user)
end
```

**Attack Scenario:**
1. Attacker steals session token via XSS, malware, or network sniffing
2. Attacker uses token from different location/device
3. Application accepts token without question
4. Attacker gains full access to victim's account

**Proposed Solution:**

**Step 1: Add Fingerprint Fields to UserToken**
```elixir
# Migration
defmodule PhoenixKit.Repo.Migrations.AddSessionFingerprintToUserTokens do
  use Ecto.Migration

  def change do
    alter table(:phoenix_kit_users_tokens) do
      add :ip_address, :string
      add :user_agent_hash, :string
      add :fingerprint_verified_at, :naive_datetime
    end

    create index(:phoenix_kit_users_tokens, [:ip_address])
    create index(:phoenix_kit_users_tokens, [:user_agent_hash])
  end
end

# Update schema
schema "phoenix_kit_users_tokens" do
  field :token, :binary
  field :context, :string
  field :sent_to, :string
  field :ip_address, :string
  field :user_agent_hash, :string
  field :fingerprint_verified_at, :naive_datetime
  belongs_to :user, PhoenixKit.Users.Auth.User

  timestamps(updated_at: false)
end
```

**Step 2: Create Fingerprinting Module**
```elixir
# lib/phoenix_kit/users/auth/session_fingerprint.ex
defmodule PhoenixKit.Users.Auth.SessionFingerprint do
  @moduledoc """
  Session fingerprinting for enhanced security.
  """

  def create_fingerprint(conn) do
    %{
      ip_address: get_ip_address(conn),
      user_agent_hash: hash_user_agent(conn)
    }
  end

  def verify_fingerprint(token, conn, opts \\ []) do
    current_fingerprint = create_fingerprint(conn)

    case token do
      %{ip_address: stored_ip, user_agent_hash: stored_ua} ->
        verify_ip = Keyword.get(opts, :verify_ip, true)
        verify_ua = Keyword.get(opts, :verify_ua, true)

        cond do
          verify_ip && stored_ip != current_fingerprint.ip_address ->
            {:error, :ip_mismatch}

          verify_ua && stored_ua != current_fingerprint.user_agent_hash ->
            {:error, :user_agent_mismatch}

          true ->
            :ok
        end

      _ ->
        # Old token without fingerprint - allow with warning
        require Logger
        Logger.warning("Token without fingerprint detected")
        :ok
    end
  end

  defp get_ip_address(conn) do
    # Check X-Forwarded-For header for proxied requests
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()
      [] ->
        conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp hash_user_agent(conn) do
    user_agent = case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> "unknown"
    end

    # Hash to prevent storing full UA string (privacy)
    :crypto.hash(:sha256, user_agent) |> Base.encode16(case: :lower)
  end
end
```

**Step 3: Update Session Token Building**
```elixir
# In UserToken module
def build_session_token(user, fingerprint) do
  token = :crypto.strong_rand_bytes(@rand_size)

  {token, %UserToken{
    token: token,
    context: "session",
    user_id: user.id,
    ip_address: fingerprint.ip_address,
    user_agent_hash: fingerprint.user_agent_hash,
    fingerprint_verified_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
  }}
end

def verify_session_token_query(token, fingerprint) do
  query =
    from token in by_token_and_context_query(token, "session"),
      join: user in assoc(token, :user),
      where: token.inserted_at > ago(@session_validity_in_days, "day"),
      # Add fingerprint verification
      where: token.ip_address == ^fingerprint.ip_address or is_nil(token.ip_address),
      where: token.user_agent_hash == ^fingerprint.user_agent_hash or is_nil(token.user_agent_hash),
      select: {user, token}

  {:ok, query}
end
```

**Step 4: Update Auth Plugs**
```elixir
# In PhoenixKitWeb.Users.Auth
def fetch_phoenix_kit_current_user(conn, _opts) do
  {user_token, conn} = ensure_user_token(conn)

  if user_token do
    fingerprint = SessionFingerprint.create_fingerprint(conn)

    case Auth.get_user_by_session_token(user_token, fingerprint) do
      {:ok, user, token} ->
        # Check fingerprint
        case SessionFingerprint.verify_fingerprint(token, conn) do
          :ok ->
            assign(conn, :phoenix_kit_current_user, user)

          {:error, reason} ->
            # Log suspicious activity
            Logger.warning("Session fingerprint mismatch: #{reason} for user #{user.id}")

            # Optionally: invalidate token
            Auth.delete_user_session_token(user_token)

            assign(conn, :phoenix_kit_current_user, nil)
        end

      nil ->
        assign(conn, :phoenix_kit_current_user, nil)
    end
  else
    assign(conn, :phoenix_kit_current_user, nil)
  end
end

def log_in_user(conn, user, params \\ %{}) do
  fingerprint = SessionFingerprint.create_fingerprint(conn)
  token = Auth.generate_user_session_token(user, fingerprint)
  # ... rest of login logic
end
```

**Configuration Options:**
```elixir
# config/config.exs
config :phoenix_kit, :session_fingerprint,
  enabled: true,
  verify_ip: true,
  verify_user_agent: true,
  allow_ip_change: false,  # Allow IP changes (mobile users)
  allow_ua_change: false   # Allow UA changes (browser updates)
```

**Privacy Considerations:**
- ✅ User-Agent is hashed, not stored in plaintext
- ✅ IP addresses are stored (required for security, disclosed in privacy policy)
- ✅ Users can view active sessions and their locations in settings

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user_token.ex`
- `lib/phoenix_kit/users/auth/session_fingerprint.ex` (new file)
- `lib/phoenix_kit_web/users/auth.ex`
- `lib/phoenix_kit/users/auth.ex`
- `priv/repo/migrations/XXX_add_session_fingerprint_to_user_tokens.exs` (new file)

---

### Issue #8: Magic Link Should Auto-Confirm Email

**Priority:** 🟠 High
**Labels:** `security`, `high`, `magic-link`, `email-verification`

**Description:**
Magic link authentication doesn't verify or confirm the user's email, allowing unconfirmed users to bypass email verification.

**Affected File:** `lib/phoenix_kit/users/magic_link.ex:125-156`

**Current Code:**
```elixir
def verify_magic_link(token) when is_binary(token) do
  case repo().one(query) do
    {user, user_token} ->
      repo().delete(user_token)
      {:ok, user}  # ← Returns user without checking/updating confirmed_at
```

**Problem:**
1. Magic link is sent to user's email
2. User clicks link and successfully authenticates
3. User's `confirmed_at` remains `nil`
4. If email confirmation is enforced elsewhere, user is blocked despite valid magic link auth

**Logic Flaw:**
If a user can authenticate via magic link sent to their email, they have proven email ownership. The email should be auto-confirmed.

**Proposed Solution:**

```elixir
def verify_magic_link(token) when is_binary(token) do
  case Base.url_decode64(token, padding: false) do
    {:ok, decoded_token} ->
      hashed_token = :crypto.hash(:sha256, decoded_token)
      expiry_minutes = get_expiry_minutes()

      query =
        from token in UserToken,
          join: user in assoc(token, :user),
          where:
            token.token == ^hashed_token and
              token.context == ^@magic_link_context and
              token.inserted_at > ago(^expiry_minutes, "minute") and
              token.sent_to == user.email,
          select: {user, token}

      case repo().one(query) do
        {user, user_token} ->
          # Use transaction to ensure atomicity
          case repo().transaction(fn ->
            # Delete the token (single-use)
            repo().delete(user_token)

            # Auto-confirm email if not already confirmed
            confirmed_user = if is_nil(user.confirmed_at) do
              Logger.info("Auto-confirming email for user #{user.id} via magic link")

              case Auth.admin_confirm_user(user) do
                {:ok, confirmed} -> confirmed
                {:error, _} -> user  # Fallback to unconfirmed if confirmation fails
              end
            else
              user
            end

            confirmed_user
          end) do
            {:ok, confirmed_user} ->
              {:ok, confirmed_user}
            {:error, reason} ->
              {:error, reason}
          end

        nil ->
          {:error, :invalid_token}
      end

    :error ->
      {:error, :invalid_token}
  end
end
```

**Alternative: Separate Confirmation from Login**
```elixir
def verify_and_confirm_magic_link(token) do
  case verify_magic_link(token) do
    {:ok, user} ->
      user = ensure_email_confirmed(user)
      {:ok, user}
    error ->
      error
  end
end

defp ensure_email_confirmed(%{confirmed_at: nil} = user) do
  case Auth.admin_confirm_user(user) do
    {:ok, confirmed_user} ->
      Events.broadcast_email_confirmed_via_magic_link(confirmed_user)
      confirmed_user
    {:error, _changeset} ->
      Logger.error("Failed to auto-confirm user #{user.id} via magic link")
      user
  end
end

defp ensure_email_confirmed(user), do: user
```

**Additional Improvements:**

1. **Log Magic Link Confirmation Events:**
```elixir
# After confirmation
Logger.info("User #{user.id} email confirmed via magic link authentication")
Events.broadcast_user_confirmed_via_magic_link(user)
```

2. **Update Magic Link Email Template:**
```elixir
# In email template
"""
Click the link below to sign in to your account.
This will also confirm your email address.

<%= @url %>

This link expires in 15 minutes.
"""
```

3. **Add Security Warning:**
```elixir
# After magic link login, show flash message
"""
Welcome! Your email has been confirmed.
For added security, consider setting a password in your account settings.
"""
```

**Testing:**
```elixir
test "magic link confirms unconfirmed user email" do
  user = insert(:user, confirmed_at: nil)
  {:ok, _user, token} = MagicLink.generate_magic_link(user.email)

  assert {:ok, confirmed_user} = MagicLink.verify_magic_link(token)
  assert confirmed_user.confirmed_at != nil
  assert_in_delta(
    NaiveDateTime.diff(confirmed_user.confirmed_at, NaiveDateTime.utc_now()),
    0,
    2
  )
end

test "magic link does not change already confirmed email" do
  original_confirmed_at = ~N[2024-01-01 12:00:00]
  user = insert(:user, confirmed_at: original_confirmed_at)
  {:ok, _user, token} = MagicLink.generate_magic_link(user.email)

  assert {:ok, confirmed_user} = MagicLink.verify_magic_link(token)
  assert confirmed_user.confirmed_at == original_confirmed_at
end
```

**Files to Modify:**
- `lib/phoenix_kit/users/magic_link.ex`
- `lib/phoenix_kit/admin/events.ex` (add new event type)
- Email templates for magic link
- `test/phoenix_kit/users/magic_link_test.exs`

---

## 📋 MEDIUM PRIORITY ISSUES

### Issue #9: Add Password Reuse Prevention

**Priority:** 🟡 Medium
**Labels:** `security`, `medium`, `password-management`

**Description:**
Users can change their password to the same value, which defeats the purpose of password change in case of suspected compromise.

**Affected File:** `lib/phoenix_kit/users/auth/user.ex:187-192`

**Current Code:**
```elixir
def password_changeset(user, attrs, opts \\ []) do
  user
  |> cast(attrs, [:password])
  |> validate_confirmation(:password, message: "does not match password")
  |> validate_password(opts)
  # ← No check if new password equals current password
end
```

**Proposed Solution:**
```elixir
def password_changeset(user, attrs, opts \\ []) do
  user
  |> cast(attrs, [:password])
  |> validate_confirmation(:password, message: "does not match password")
  |> validate_password_not_same_as_current()
  |> validate_password(opts)
end

defp validate_password_not_same_as_current(changeset) do
  new_password = get_change(changeset, :password)
  current_hashed = changeset.data.hashed_password

  if new_password && current_hashed do
    if Bcrypt.verify_pass(new_password, current_hashed) do
      add_error(changeset, :password, "must be different from your current password")
    else
      changeset
    end
  else
    changeset
  end
end
```

**Optional: Password History (Advanced)**
```elixir
# Add password history table
create table(:phoenix_kit_user_password_history) do
  add :user_id, references(:phoenix_kit_users, on_delete: :delete_all), null: false
  add :hashed_password, :string, null: false
  timestamps(updated_at: false)
end

# Check against last N passwords
def validate_password_not_in_history(changeset, history_size \\ 5) do
  new_password = get_change(changeset, :password)
  user_id = changeset.data.id

  if new_password && user_id do
    recent_passwords = get_recent_password_hashes(user_id, history_size)

    if Enum.any?(recent_passwords, &Bcrypt.verify_pass(new_password, &1)) do
      add_error(changeset, :password, "cannot reuse one of your last #{history_size} passwords")
    else
      changeset
    end
  else
    changeset
  end
end
```

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user.ex`
- `test/phoenix_kit/users/auth/user_test.exs`

---

### Issue #10: Secure Remember Me Cookie Settings

**Priority:** 🟡 Medium
**Labels:** `security`, `medium`, `cookies`, `session-management`

**Description:**
Remember me cookie lacks explicit `http_only` and `secure` flags, potentially exposing it to XSS attacks and transmission over insecure connections.

**Affected File:** `lib/phoenix_kit_web/users/auth.ex:37`

**Current Code:**
```elixir
@remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]
```

**Missing Security Flags:**
- `http_only: true` - Prevents JavaScript access (XSS protection)
- `secure: true` - HTTPS-only transmission (MITM protection)

**Proposed Solution:**
```elixir
@remember_me_options [
  sign: true,
  max_age: @max_age,
  same_site: "Lax",
  http_only: true,  # Prevent XSS attacks
  secure: Application.compile_env(:phoenix_kit, :secure_cookies, true)  # HTTPS only in production
]

# Alternative: Dynamic configuration
defp remember_me_options do
  base_options = [
    sign: true,
    max_age: @max_age,
    same_site: "Lax",
    http_only: true
  ]

  # Only enforce secure flag in production
  if Application.get_env(:phoenix_kit, :env) == :prod do
    Keyword.put(base_options, :secure, true)
  else
    base_options
  end
end
```

**Configuration:**
```elixir
# config/prod.exs
config :phoenix_kit,
  secure_cookies: true

# config/dev.exs
config :phoenix_kit,
  secure_cookies: false  # Allow HTTP in development
```

**Files to Modify:**
- `lib/phoenix_kit_web/users/auth.ex`
- `config/prod.exs` and `config/dev.exs`

---

### Issue #11: Enhance Audit Logging for Admin Actions

**Priority:** 🟡 Medium
**Labels:** `security`, `medium`, `audit-logging`, `compliance`

**Description:**
Admin password reset and other sensitive operations lack comprehensive audit trails (who, when, where, why).

**Affected Files:**
- `lib/phoenix_kit/users/auth.ex:387-399`
- `lib/phoenix_kit/users/roles.ex` (role assignment operations)

**Current Code:**
```elixir
def admin_update_user_password(user, attrs) do
  changeset = User.password_changeset(user, attrs)
  # No audit log of WHO performed action, from WHERE, and WHEN

  Ecto.Multi.new()
  |> Ecto.Multi.update(:user, changeset)
  |> Ecto.Multi.delete_all(:tokens, UserToken.by_user_and_contexts_query(user, :all))
  |> Repo.transaction()
end
```

**Proposed Solution:**

**Step 1: Create Audit Log Schema**
```elixir
# lib/phoenix_kit/admin/audit_log.ex
defmodule PhoenixKit.Admin.AuditLog do
  use Ecto.Schema
  import Ecto.Changeset

  schema "phoenix_kit_audit_logs" do
    field :action, :string
    field :resource_type, :string
    field :resource_id, :integer
    field :actor_id, :integer
    field :actor_email, :string
    field :ip_address, :string
    field :user_agent, :string
    field :metadata, :map
    field :success, :boolean

    belongs_to :actor, PhoenixKit.Users.Auth.User, define_field: false

    timestamps(updated_at: false)
  end

  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, [
      :action, :resource_type, :resource_id,
      :actor_id, :actor_email, :ip_address,
      :user_agent, :metadata, :success
    ])
    |> validate_required([:action, :resource_type])
  end
end

# Migration
defmodule PhoenixKit.Repo.Migrations.CreateAuditLogs do
  use Ecto.Migration

  def change do
    create table(:phoenix_kit_audit_logs) do
      add :action, :string, null: false
      add :resource_type, :string, null: false
      add :resource_id, :integer
      add :actor_id, references(:phoenix_kit_users, on_delete: :nilify_all)
      add :actor_email, :string
      add :ip_address, :string
      add :user_agent, :string
      add :metadata, :jsonb
      add :success, :boolean, default: true

      timestamps(updated_at: false)
    end

    create index(:phoenix_kit_audit_logs, [:action])
    create index(:phoenix_kit_audit_logs, [:resource_type, :resource_id])
    create index(:phoenix_kit_audit_logs, [:actor_id])
    create index(:phoenix_kit_audit_logs, [:inserted_at])
  end
end
```

**Step 2: Add Audit Logging Helper**
```elixir
# lib/phoenix_kit/admin/audit.ex
defmodule PhoenixKit.Admin.Audit do
  import Ecto.Query
  alias PhoenixKit.Admin.AuditLog
  alias PhoenixKit.RepoHelper, as: Repo

  @doc """
  Logs an audit event.
  """
  def log(action, resource_type, resource_id, context) do
    %AuditLog{}
    |> AuditLog.changeset(%{
      action: to_string(action),
      resource_type: to_string(resource_type),
      resource_id: resource_id,
      actor_id: context[:actor_id],
      actor_email: context[:actor_email],
      ip_address: context[:ip_address],
      user_agent: context[:user_agent],
      metadata: context[:metadata] || %{},
      success: context[:success] != false
    })
    |> Repo.insert()
  end

  @doc """
  Logs password change.
  """
  def log_password_change(target_user, admin_user, context \\ %{}) do
    log(
      :password_reset,
      :user,
      target_user.id,
      Map.merge(context, %{
        actor_id: admin_user && admin_user.id,
        actor_email: admin_user && admin_user.email,
        metadata: %{
          target_email: target_user.email,
          reset_type: context[:reset_type] || :admin_reset
        }
      })
    )
  end

  @doc """
  Logs role assignment.
  """
  def log_role_assignment(user, role_name, assigned_by, context \\ %{}) do
    log(
      :role_assigned,
      :user,
      user.id,
      Map.merge(context, %{
        actor_id: assigned_by && assigned_by.id,
        actor_email: assigned_by && assigned_by.email,
        metadata: %{
          user_email: user.email,
          role_name: role_name
        }
      })
    )
  end

  @doc """
  Gets audit logs for a user.
  """
  def get_user_audit_logs(user_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(log in AuditLog,
      where: log.resource_type == "user" and log.resource_id == ^user_id,
      order_by: [desc: log.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Gets audit logs by actor.
  """
  def get_actor_audit_logs(actor_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(log in AuditLog,
      where: log.actor_id == ^actor_id,
      order_by: [desc: log.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end
end
```

**Step 3: Update Admin Functions**
```elixir
# In Auth module
def admin_update_user_password(user, attrs, context \\ %{}) do
  changeset = User.password_changeset(user, attrs)

  result =
    Ecto.Multi.new()
    |> Ecto.Multi.update(:user, changeset)
    |> Ecto.Multi.delete_all(:tokens, UserToken.by_user_and_contexts_query(user, :all))
    |> Repo.transaction()

  case result do
    {:ok, %{user: updated_user}} ->
      # Log successful password change
      PhoenixKit.Admin.Audit.log_password_change(
        updated_user,
        context[:admin_user],
        Map.take(context, [:ip_address, :user_agent])
      )

      {:ok, updated_user}

    error ->
      # Log failed attempt
      if context[:admin_user] do
        PhoenixKit.Admin.Audit.log(
          :password_reset_failed,
          :user,
          user.id,
          Map.merge(context, %{success: false})
        )
      end

      error
  end
end

# In Roles module
def assign_role(user, role_name, assigned_by, context \\ %{}) do
  # ... existing assignment logic ...

  case result do
    {:ok, assignment} ->
      PhoenixKit.Admin.Audit.log_role_assignment(
        user,
        role_name,
        assigned_by,
        context
      )
      {:ok, assignment}

    error ->
      error
  end
end
```

**Step 4: Add Audit Log Viewer (LiveView)**
```elixir
# lib/phoenix_kit_web/live/admin/audit_logs_live.ex
defmodule PhoenixKitWeb.Live.Admin.AuditLogsLive do
  use PhoenixKitWeb, :live_view

  def render(assigns) do
    ~H"""
    <div class="audit-logs">
      <h1>Security Audit Logs</h1>

      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Resource</th>
            <th>IP Address</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <%= for log <- @logs do %>
            <tr>
              <td><%= log.inserted_at %></td>
              <td><%= log.action %></td>
              <td><%= log.actor_email || "System" %></td>
              <td><%= log.resource_type %> #<%= log.resource_id %></td>
              <td><%= log.ip_address %></td>
              <td><%= if log.success, do: "✓", else: "✗" %></td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>
    """
  end
end
```

**Files to Modify:**
- `lib/phoenix_kit/admin/audit_log.ex` (new schema)
- `lib/phoenix_kit/admin/audit.ex` (new module)
- `lib/phoenix_kit/users/auth.ex`
- `lib/phoenix_kit/users/roles.ex`
- `lib/phoenix_kit_web/live/admin/audit_logs_live.ex` (new LiveView)
- `priv/repo/migrations/XXX_create_audit_logs.exs` (new migration)

**Compliance Benefits:**
- ✅ SOC 2 compliance requirement
- ✅ GDPR audit trail requirement
- ✅ PCI DSS access logging
- ✅ Forensic investigation capability

---

### Issue #12: Fix Race Condition in First Owner Assignment

**Priority:** 🟡 Medium
**Labels:** `security`, `medium`, `concurrency`, `roles`

**Description:**
Race condition in `ensure_first_user_is_owner` during concurrent registrations could result in multiple owners or no owner.

**Affected File:** `lib/phoenix_kit/users/roles.ex:706-747`

**Current Code:**
```elixir
def ensure_first_user_is_owner(%User{} = user) do
  repo.transaction(fn ->
    # Lock the Owner role
    owner_role = repo.one(from r in Role, where: r.name == ^roles.owner, lock: "FOR UPDATE")

    # Check for existing owners (RACE CONDITION HERE)
    existing_owner = repo.one(
      from assignment in RoleAssignment,
        join: u in User,
        on: assignment.user_id == u.id,
        where: assignment.role_id == ^owner_role.id,
        where: u.is_active == true,
        limit: 1
    )
    # ← Between lock and check, another transaction could be in progress
```

**Race Condition Scenario:**
```
Time  | Transaction A                  | Transaction B
------|--------------------------------|--------------------------------
T1    | Lock Owner role               | Lock Owner role (waits)
T2    | Check owners (count: 0)       | (waiting for lock)
T3    | Assign Owner to User A        | (waiting)
T4    | COMMIT                        | Check owners (count: 1)
T5    |                               | Assign User role to User B ✓
```

**Proposed Solution:**

**Option 1: Atomic Query with Lock**
```elixir
def ensure_first_user_is_owner(%User{} = user) do
  repo = RepoHelper.repo()
  roles = Role.system_roles()

  repo.transaction(fn ->
    # Perform atomic count with lock in single query
    result = repo.one(
      from r in Role,
        left_join: assignment in RoleAssignment,
        on: assignment.role_id == r.id,
        left_join: u in User,
        on: assignment.user_id == u.id and u.is_active == true,
        where: r.name == ^roles.owner,
        lock: "FOR UPDATE",
        select: {r, count(u.id, :distinct)}
    )

    case result do
      {owner_role, 0} ->
        # No active owners exist, make this user Owner
        assign_owner_role(user, owner_role, repo)

      {_owner_role, _count} ->
        # Owners exist, assign default role
        assign_default_role(user, repo)
    end
  end)
end

defp assign_owner_role(user, owner_role, repo) do
  case assign_role_internal(user, owner_role.name) do
    {:ok, _} -> :owner
    {:error, reason} -> repo.rollback(reason)
  end
end

defp assign_default_role(user, repo) do
  default_role = get_safe_default_role()

  case assign_role_internal(user, default_role) do
    {:ok, _} -> String.to_atom(String.downcase(default_role))
    {:error, reason} -> repo.rollback(reason)
  end
end
```

**Option 2: Database-Level Constraint**
```elixir
# Migration to add partial unique index
defmodule PhoenixKit.Repo.Migrations.AddOwnerConstraint do
  use Ecto.Migration

  def up do
    # Create function to ensure only one active owner
    execute """
    CREATE OR REPLACE FUNCTION check_single_owner()
    RETURNS TRIGGER AS $$
    DECLARE
      owner_role_id INTEGER;
      owner_count INTEGER;
    BEGIN
      -- Get Owner role ID
      SELECT id INTO owner_role_id
      FROM phoenix_kit_user_roles
      WHERE name = 'Owner';

      -- Count active owners (excluding current row if UPDATE)
      SELECT COUNT(*) INTO owner_count
      FROM phoenix_kit_user_role_assignments ra
      JOIN phoenix_kit_users u ON ra.user_id = u.id
      WHERE ra.role_id = owner_role_id
        AND u.is_active = true
        AND (TG_OP = 'INSERT' OR ra.id != NEW.id);

      -- Allow if no other active owners exist
      IF NEW.role_id = owner_role_id AND owner_count > 0 THEN
        RAISE EXCEPTION 'Only one active Owner is allowed';
      END IF;

      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """

    execute """
    CREATE TRIGGER enforce_single_owner
    BEFORE INSERT OR UPDATE ON phoenix_kit_user_role_assignments
    FOR EACH ROW
    EXECUTE FUNCTION check_single_owner();
    """
  end

  def down do
    execute "DROP TRIGGER IF EXISTS enforce_single_owner ON phoenix_kit_user_role_assignments;"
    execute "DROP FUNCTION IF EXISTS check_single_owner();"
  end
end
```

**Option 3: Application-Level Mutex**
```elixir
defmodule PhoenixKit.Users.Roles.OwnerMutex do
  use GenServer

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def acquire(fun) do
    GenServer.call(__MODULE__, {:acquire, fun}, :infinity)
  end

  def init(_) do
    {:ok, %{locked: false, queue: []}}
  end

  def handle_call({:acquire, fun}, from, %{locked: false} = state) do
    # Execute function while holding lock
    result = fun.()
    {:reply, result, state}
  end

  def handle_call({:acquire, _fun}, from, %{locked: true} = state) do
    # Add to queue if locked
    {:noreply, %{state | queue: state.queue ++ [from]}}
  end
end

# Usage
def ensure_first_user_is_owner(%User{} = user) do
  OwnerMutex.acquire(fn ->
    # Original implementation with transaction
    # Now protected by application-level mutex
  end)
end
```

**Testing:**
```elixir
test "concurrent registrations result in only one owner" do
  # Simulate concurrent user registrations
  tasks = for i <- 1..10 do
    Task.async(fn ->
      {:ok, user} = Auth.register_user(%{
        email: "user#{i}@example.com",
        password: "password123456"
      })

      Auth.user_has_role?(user, "Owner")
    end)
  end

  results = Task.await_many(tasks, 10_000)
  owner_count = Enum.count(results, & &1 == true)

  # Exactly one user should be Owner
  assert owner_count == 1

  # Verify in database
  db_owner_count = Roles.count_active_owners()
  assert db_owner_count == 1
end
```

**Recommendation:** Use **Option 1 (Atomic Query)** for simplicity and **Option 2 (Database Constraint)** as additional safety net.

**Files to Modify:**
- `lib/phoenix_kit/users/roles.ex`
- `priv/repo/migrations/XXX_add_owner_constraint.exs` (optional)
- `test/phoenix_kit/users/roles_test.exs`

---

## 🔵 LOW PRIORITY IMPROVEMENTS

### Issue #13: Centralize Inactive User Handling

**Priority:** 🔵 Low
**Labels:** `refactoring`, `code-quality`, `security`

**Description:**
Inactive user checks are scattered across multiple files with inconsistent implementation, making maintenance difficult.

**Affected Files:**
- `lib/phoenix_kit_web/users/auth.ex:163-177`
- `lib/phoenix_kit_web/users/auth.ex:196-210`
- `lib/phoenix_kit_web/users/auth.ex:409-424`

**Current Code (Duplicated 3 times):**
```elixir
case user do
  %{is_active: false} = inactive_user ->
    require Logger
    Logger.warning("PhoenixKit: Inactive user #{inactive_user.id} attempted access")
    nil
  active_user ->
    active_user
end
```

**Proposed Solution:**

**Step 1: Create Central Module**
```elixir
# lib/phoenix_kit/users/auth/access_control.ex
defmodule PhoenixKit.Users.Auth.AccessControl do
  @moduledoc """
  Centralized access control logic for user authentication.
  """

  require Logger

  @doc """
  Ensures user is active, returns nil if inactive.
  """
  def ensure_active_user(%{is_active: false} = user) do
    Logger.warning("PhoenixKit: Inactive user #{user.id} attempted access, blocking")

    # Optional: Track failed access attempts
    track_inactive_access_attempt(user)

    nil
  end

  def ensure_active_user(user), do: user

  @doc """
  Ensures user is active and confirmed.
  """
  def ensure_active_and_confirmed_user(user, opts \\ []) do
    require_confirmation = Keyword.get(opts, :require_confirmation, false)

    case user do
      %{is_active: false} = inactive_user ->
        Logger.warning("Inactive user #{inactive_user.id} blocked")
        nil

      %{confirmed_at: nil} when require_confirmation ->
        Logger.info("Unconfirmed user #{user.id} blocked")
        nil

      active_user ->
        active_user
    end
  end

  @doc """
  Checks if user can access protected resource.
  """
  def can_access?(user, resource_type \\ :general)
  def can_access?(nil, _), do: false
  def can_access?(%{is_active: false}, _), do: false
  def can_access?(%{confirmed_at: nil}, :protected), do: false
  def can_access?(_user, _), do: true

  # Private helpers

  defp track_inactive_access_attempt(user) do
    # Could store in cache or database for security monitoring
    :telemetry.execute(
      [:phoenix_kit, :auth, :inactive_access],
      %{count: 1},
      %{user_id: user.id}
    )
  end
end
```

**Step 2: Update Auth Functions**
```elixir
# In PhoenixKitWeb.Users.Auth
alias PhoenixKit.Users.Auth.AccessControl

def fetch_phoenix_kit_current_user(conn, _opts) do
  {user_token, conn} = ensure_user_token(conn)
  user = user_token && Auth.get_user_by_session_token(user_token)

  # Use centralized access control
  active_user = AccessControl.ensure_active_user(user)

  assign(conn, :phoenix_kit_current_user, active_user)
end

defp get_active_user_from_token(user_token) do
  user = Auth.get_user_by_session_token(user_token)
  AccessControl.ensure_active_user(user)
end
```

**Step 3: Add Telemetry Monitoring**
```elixir
# In application.ex
def start(_type, _args) do
  # Attach telemetry handler for inactive access monitoring
  :telemetry.attach(
    "phoenix_kit-inactive-access",
    [:phoenix_kit, :auth, :inactive_access],
    &PhoenixKit.Telemetry.handle_inactive_access/4,
    nil
  )

  # ... rest of supervision tree
end

# lib/phoenix_kit/telemetry.ex
defmodule PhoenixKit.Telemetry do
  def handle_inactive_access(_event, measurements, metadata, _config) do
    # Could send to monitoring service, log aggregation, etc.
    Logger.warning("""
    Inactive user access attempt detected:
    User ID: #{metadata.user_id}
    Count: #{measurements.count}
    """)
  end
end
```

**Benefits:**
- ✅ Single source of truth
- ✅ Easier to modify behavior
- ✅ Consistent logging format
- ✅ Telemetry integration
- ✅ Testability

**Files to Modify:**
- `lib/phoenix_kit/users/auth/access_control.ex` (new)
- `lib/phoenix_kit_web/users/auth.ex`
- `lib/phoenix_kit/telemetry.ex`
- `lib/phoenix_kit/application.ex`

---

### Issue #14: Make Password Requirements Configurable

**Priority:** 🔵 Low
**Labels:** `enhancement`, `password-security`, `configuration`

**Description:**
Password strength requirements are hardcoded with commented-out additional validations, making it difficult to customize per deployment.

**Affected File:** `lib/phoenix_kit/users/auth/user.ex:122-131`

**Current Code:**
```elixir
defp validate_password(changeset, opts) do
  changeset
  |> validate_required([:password])
  |> validate_length(:password, min: 8, max: 72)
  # Examples of additional password validation:
  # |> validate_format(:password, ~r/[a-z]/, message: "at least one lower case character")
  # |> validate_format(:password, ~r/[A-Z]/, message: "at least one upper case character")
  # |> validate_format(:password, ~r/[!?@#$%^&*_0-9]/, message: "at least one digit or punctuation character")
  |> maybe_hash_password(opts)
end
```

**Proposed Solution:**

**Step 1: Configuration Schema**
```elixir
# config/config.exs
config :phoenix_kit, :password_requirements,
  min_length: 8,
  max_length: 72,
  require_uppercase: false,
  require_lowercase: false,
  require_digit: false,
  require_special: false,
  special_characters: "!?@#$%^&*_-+=",
  min_unique_characters: 0,
  check_common_passwords: false,
  check_breach_database: false

# config/prod.exs (stricter for production)
config :phoenix_kit, :password_requirements,
  min_length: 12,
  require_uppercase: true,
  require_lowercase: true,
  require_digit: true,
  require_special: true,
  min_unique_characters: 5,
  check_common_passwords: true
```

**Step 2: Password Validator Module**
```elixir
# lib/phoenix_kit/users/auth/password_validator.ex
defmodule PhoenixKit.Users.Auth.PasswordValidator do
  @moduledoc """
  Configurable password validation.
  """

  import Ecto.Changeset

  @doc """
  Validates password against configured requirements.
  """
  def validate_password_requirements(changeset) do
    requirements = get_requirements()

    changeset
    |> validate_length(:password,
        min: requirements.min_length,
        max: requirements.max_length)
    |> validate_character_requirements(requirements)
    |> validate_unique_characters(requirements.min_unique_characters)
    |> validate_common_passwords(requirements.check_common_passwords)
    |> validate_breach_database(requirements.check_breach_database)
  end

  defp validate_character_requirements(changeset, requirements) do
    changeset
    |> validate_uppercase(requirements.require_uppercase)
    |> validate_lowercase(requirements.require_lowercase)
    |> validate_digit(requirements.require_digit)
    |> validate_special(requirements.require_special, requirements.special_characters)
  end

  defp validate_uppercase(changeset, true) do
    validate_format(changeset, :password, ~r/[A-Z]/,
      message: "must contain at least one uppercase letter")
  end
  defp validate_uppercase(changeset, false), do: changeset

  defp validate_lowercase(changeset, true) do
    validate_format(changeset, :password, ~r/[a-z]/,
      message: "must contain at least one lowercase letter")
  end
  defp validate_lowercase(changeset, false), do: changeset

  defp validate_digit(changeset, true) do
    validate_format(changeset, :password, ~r/[0-9]/,
      message: "must contain at least one digit")
  end
  defp validate_digit(changeset, false), do: changeset

  defp validate_special(changeset, true, special_chars) do
    pattern = ~r/[#{Regex.escape(special_chars)}]/
    validate_format(changeset, :password, pattern,
      message: "must contain at least one special character (#{special_chars})")
  end
  defp validate_special(changeset, false, _), do: changeset

  defp validate_unique_characters(changeset, 0), do: changeset
  defp validate_unique_characters(changeset, min_unique) do
    password = get_change(changeset, :password)

    if password do
      unique_chars = password |> String.graphemes() |> Enum.uniq() |> length()

      if unique_chars < min_unique do
        add_error(changeset, :password,
          "must contain at least #{min_unique} unique characters")
      else
        changeset
      end
    else
      changeset
    end
  end

  defp validate_common_passwords(changeset, false), do: changeset
  defp validate_common_passwords(changeset, true) do
    password = get_change(changeset, :password)

    if password && is_common_password?(password) do
      add_error(changeset, :password,
        "is too common. Please choose a more unique password")
    else
      changeset
    end
  end

  defp validate_breach_database(changeset, false), do: changeset
  defp validate_breach_database(changeset, true) do
    password = get_change(changeset, :password)

    if password && is_breached_password?(password) do
      add_error(changeset, :password,
        "has been found in a data breach. Please choose a different password")
    else
      changeset
    end
  end

  # Private helpers

  defp get_requirements do
    defaults = %{
      min_length: 8,
      max_length: 72,
      require_uppercase: false,
      require_lowercase: false,
      require_digit: false,
      require_special: false,
      special_characters: "!?@#$%^&*_-+=",
      min_unique_characters: 0,
      check_common_passwords: false,
      check_breach_database: false
    }

    config = Application.get_env(:phoenix_kit, :password_requirements, [])
    Map.merge(defaults, Enum.into(config, %{}))
  end

  defp is_common_password?(password) do
    # Check against list of common passwords
    common_passwords = load_common_passwords()
    String.downcase(password) in common_passwords
  end

  defp is_breached_password?(password) do
    # Check against Have I Been Pwned API
    # Implementation would use k-anonymity model
    false  # Placeholder
  end

  defp load_common_passwords do
    # Load from file or cache
    # For now, return small sample
    [
      "password", "123456", "password123", "qwerty",
      "abc123", "letmein", "welcome", "monkey",
      "dragon", "master", "sunshine", "princess"
    ]
  end
end
```

**Step 3: Update User Schema**
```elixir
# In User module
defp validate_password(changeset, opts) do
  changeset
  |> validate_required([:password])
  |> PasswordValidator.validate_password_requirements()
  |> maybe_hash_password(opts)
end
```

**Step 4: Add Password Strength Indicator (Frontend)**
```heex
<%!-- In registration form --%>
<div class="password-field">
  <input type="password" name="password" id="password" phx-hook="PasswordStrength" />

  <div id="password-strength" class="hidden">
    <div class="strength-meter"></div>
    <ul class="requirements">
      <li data-requirement="length">At least 12 characters</li>
      <li data-requirement="uppercase">One uppercase letter</li>
      <li data-requirement="lowercase">One lowercase letter</li>
      <li data-requirement="digit">One number</li>
      <li data-requirement="special">One special character</li>
    </ul>
  </div>
</div>

<script>
// Phoenix LiveView Hook
Hooks.PasswordStrength = {
  mounted() {
    this.el.addEventListener('input', (e) => {
      const password = e.target.value
      this.checkRequirements(password)
    })
  },

  checkRequirements(password) {
    const requirements = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      digit: /[0-9]/.test(password),
      special: /[!?@#$%^&*_\-+=]/.test(password)
    }

    // Update UI based on requirements
    Object.entries(requirements).forEach(([req, met]) => {
      const el = document.querySelector(`[data-requirement="${req}"]`)
      el.classList.toggle('met', met)
      el.classList.toggle('unmet', !met)
    })
  }
}
</script>
```

**Files to Modify:**
- `lib/phoenix_kit/users/auth/password_validator.ex` (new)
- `lib/phoenix_kit/users/auth/user.ex`
- `config/config.exs`, `config/prod.exs`
- Password input components (LiveView)
- `priv/static/assets/password_strength.js` (optional)

---

### Issue #15: Reduce Magic Link Expiry Time

**Priority:** 🔵 Low
**Labels:** `security`, `low`, `magic-link`, `tokens`

**Description:**
Magic link tokens are valid for 24 hours, which is excessive for passwordless authentication. Industry standard is 15-30 minutes.

**Affected Files:**
- `lib/phoenix_kit/users/auth/user_token.ex:35`
- `lib/phoenix_kit/users/magic_link.ex:65`

**Current Code:**
```elixir
# In UserToken
@magic_link_validity_in_days 1  # 24 hours!

# In MagicLink
@default_expiry_minutes 15  # Correct, but not used by UserToken
```

**Problem:**
The `UserToken` module defines magic link expiry as 1 day, but the `MagicLink` module attempts to use 15 minutes. There's a mismatch.

**Current Verification:**
```elixir
# In UserToken.ex
defp days_for_context("magic_link"), do: @magic_link_validity_in_days

# But MagicLink.ex uses its own expiry:
def verify_magic_link(token) do
  expiry_minutes = get_expiry_minutes()  # 15 minutes

  query =
    from token in UserToken,
      where: token.inserted_at > ago(^expiry_minutes, "minute")
```

**Proposed Solution:**

**Option 1: Standardize on Minutes**
```elixir
# In UserToken.ex
@reset_password_validity_in_hours 1
@confirm_validity_in_days 7
@change_email_validity_in_days 7
@session_validity_in_days 60
@magic_link_validity_in_minutes 15  # Changed to minutes

defp expiry_for_context("confirm"), do: {:days, @confirm_validity_in_days}
defp expiry_for_context("reset_password"), do: {:hours, @reset_password_validity_in_hours}
defp expiry_for_context("magic_link"), do: {:minutes, @magic_link_validity_in_minutes}

def verify_email_token_query(token, context) do
  case Base.url_decode64(token, padding: false) do
    {:ok, decoded_token} ->
      hashed_token = :crypto.hash(@hash_algorithm, decoded_token)
      {unit, amount} = expiry_for_context(context)

      query =
        from token in by_token_and_context_query(hashed_token, context),
          join: user in assoc(token, :user),
          where: token.inserted_at > ago(^amount, ^to_string(unit)),
          where: token.sent_to == user.email,
          select: user

      {:ok, query}
    :error ->
      :error
  end
end
```

**Option 2: Separate Verification for Magic Links**
```elixir
# Keep UserToken generic, handle magic link verification separately
# In MagicLink.ex - already implemented correctly!

# Just remove the days_for_context for magic_link from UserToken
# And document that magic links use their own verification
```

**Option 3: Configurable Expiry**
```elixir
# config/config.exs
config :phoenix_kit, :token_expiry,
  magic_link_minutes: 15,
  reset_password_hours: 1,
  confirm_email_days: 7

# In MagicLink.ex
defp get_expiry_minutes do
  Application.get_env(:phoenix_kit, :token_expiry, [])
  |> Keyword.get(:magic_link_minutes, 15)
end
```

**Security Comparison:**

| Expiry Time | Security | UX       | Use Case                    |
|-------------|----------|----------|-----------------------------|
| 5 minutes   | Highest  | Poor     | High-security applications  |
| 15 minutes  | High     | Good     | **Recommended default**     |
| 30 minutes  | Medium   | Good     | User-friendly applications  |
| 1 hour      | Low      | Excellent| Development only            |
| 24 hours    | Very Low | Excellent| **Not recommended**         |

**Recommendation:** Use **15 minutes** (current MagicLink implementation) and remove the 1-day constant from UserToken.

**Files to Modify:**
- `lib/phoenix_kit/users/auth/user_token.ex`
- `lib/phoenix_kit/users/magic_link.ex`
- Documentation (README, moduledocs)

---

## 📚 ADDITIONAL RECOMMENDATIONS

### Recommendation #1: Implement Account Lockout

**Description:**
Add temporary account lockout after N failed login attempts to prevent brute-force attacks.

```elixir
defmodule PhoenixKit.Users.Auth.AccountLockout do
  @max_attempts 5
  @lockout_duration_minutes 15

  def record_failed_attempt(email) do
    # Use Cachex or ETS for temporary storage
    key = "failed_login:#{email}"

    case Cachex.incr(:phoenix_kit_cache, key) do
      {:ok, count} when count >= @max_attempts ->
        Cachex.expire(:phoenix_kit_cache, key, :timer.minutes(@lockout_duration_minutes))
        {:error, :account_locked}

      {:ok, _count} ->
        Cachex.expire(:phoenix_kit_cache, key, :timer.minutes(@lockout_duration_minutes))
        :ok
    end
  end

  def check_lockout(email) do
    key = "failed_login:#{email}"

    case Cachex.get(:phoenix_kit_cache, key) do
      {:ok, count} when count >= @max_attempts ->
        {:error, :account_locked, remaining_time(key)}
      _ ->
        :ok
    end
  end

  def clear_attempts(email) do
    Cachex.del(:phoenix_kit_cache, "failed_login:#{email}")
  end

  defp remaining_time(key) do
    case Cachex.ttl(:phoenix_kit_cache, key) do
      {:ok, milliseconds} -> div(milliseconds, 60_000)
      _ -> @lockout_duration_minutes
    end
  end
end
```

---

### Recommendation #2: Add Multi-Factor Authentication (MFA)

**Description:**
Implement TOTP-based 2FA for enhanced account security.

```elixir
# Add to User schema
field :totp_secret, :string, redact: true
field :totp_enabled, :boolean, default: false
field :backup_codes, {:array, :string}, redact: true, default: []
field :totp_enabled_at, :naive_datetime

# TOTP module
defmodule PhoenixKit.Users.Auth.TOTP do
  def generate_secret do
    :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)
  end

  def verify_token(secret, token) do
    NimbleTOTP.valid?(secret, token, window: 1)
  end

  def generate_qr_code(user, secret) do
    uri = "otpauth://totp/PhoenixKit:#{user.email}?secret=#{secret}&issuer=PhoenixKit"
    QRCode.create(uri)
  end

  def generate_backup_codes(count \\ 10) do
    for _ <- 1..count do
      :crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)
    end
  end
end
```

---

### Recommendation #3: Implement Security Events Dashboard

**Description:**
Create a security monitoring dashboard for administrators.

```elixir
defmodule PhoenixKitWeb.Live.SecurityDashboardLive do
  use PhoenixKitWeb, :live_view

  def render(assigns) do
    ~H"""
    <div class="security-dashboard">
      <h1>Security Monitoring</h1>

      <div class="metrics">
        <div class="metric">
          <h3>Failed Login Attempts (24h)</h3>
          <span class="value"><%= @failed_logins %></span>
        </div>

        <div class="metric">
          <h3>Account Lockouts (24h)</h3>
          <span class="value"><%= @lockouts %></span>
        </div>

        <div class="metric">
          <h3>Suspicious Activity</h3>
          <span class="value"><%= @suspicious_activity %></span>
        </div>
      </div>

      <div class="recent-events">
        <h2>Recent Security Events</h2>
        <table>
          <%= for event <- @events do %>
            <tr>
              <td><%= event.timestamp %></td>
              <td><%= event.type %></td>
              <td><%= event.user_email %></td>
              <td><%= event.ip_address %></td>
            </tr>
          <% end %>
        </table>
      </div>
    </div>
    """
  end
end
```

---

### Recommendation #4: Add Password Breach Detection

**Description:**
Integrate with Have I Been Pwned API to check passwords against known breaches.

```elixir
defmodule PhoenixKit.Users.Auth.PasswordBreach do
  @api_url "https://api.pwnedpasswords.com/range/"

  def is_compromised?(password) do
    # Use k-anonymity model (send only first 5 chars of SHA-1 hash)
    hash = :crypto.hash(:sha, password) |> Base.encode16()
    prefix = String.slice(hash, 0, 5)
    suffix = String.slice(hash, 5..-1)

    case HTTPoison.get("#{@api_url}#{prefix}") do
      {:ok, %{body: body, status_code: 200}} ->
        body
        |> String.split("\n")
        |> Enum.any?(fn line ->
          String.starts_with?(line, suffix)
        end)

      _ ->
        # Fail open (don't block if API is down)
        false
    end
  end
end
```

---

## 🎯 IMPLEMENTATION PRIORITY

### Phase 1: Critical (Week 1)
1. ✅ Issue #2: Rate Limiting
2. ✅ Issue #1: Timing Attack Fix
3. ✅ Issue #3: Password Reset Token Expiry

### Phase 2: High Priority (Week 2-3)
4. ✅ Issue #5: Email Confirmation Enforcement
5. ✅ Issue #6: Username Generation Fix
6. ✅ Issue #7: Session Fingerprinting
7. ✅ Issue #4: Magic Link Token Size

### Phase 3: Medium Priority (Month 1)
8. ✅ Issue #9: Password Reuse Prevention
9. ✅ Issue #11: Audit Logging
10. ✅ Issue #12: Race Condition Fix
11. ✅ Issue #8: Magic Link Email Confirmation

### Phase 4: Low Priority (Month 2-3)
12. ✅ Issue #13: Centralize Inactive User Handling
13. ✅ Issue #14: Configurable Password Requirements
14. ✅ Issue #15: Magic Link Expiry
15. ✅ Issue #10: Cookie Security Flags

### Phase 5: Enhancements (Backlog)
16. ✅ Account Lockout
17. ✅ Multi-Factor Authentication
18. ✅ Security Dashboard
19. ✅ Password Breach Detection

---

## 📊 TESTING REQUIREMENTS

For each issue, comprehensive tests should be added:

### Security Test Examples

```elixir
# Test rate limiting
test "blocks login after 5 failed attempts" do
  email = "user@example.com"

  # Make 5 failed attempts
  for _ <- 1..5 do
    assert is_nil(Auth.get_user_by_email_and_password(email, "wrong"))
  end

  # 6th attempt should be rate limited
  assert is_nil(Auth.get_user_by_email_and_password(email, "correct"))
end

# Test timing attack resistance
test "magic link generation has consistent timing" do
  existing_email = "user@example.com"
  fake_email = "nonexistent@example.com"

  create_user(%{email: existing_email})

  {time1, _} = :timer.tc(fn -> MagicLink.generate_magic_link(existing_email) end)
  {time2, _} = :timer.tc(fn -> MagicLink.generate_magic_link(fake_email) end)

  # Times should be within 10% of each other
  diff = abs(time1 - time2) / max(time1, time2) * 100
  assert diff < 10
end

# Test session fingerprint
test "rejects session token from different IP" do
  user = create_user()
  token = create_session_token(user, %{ip: "192.168.1.1"})

  # Try to use token from different IP
  conn = build_conn(:get, "/")
         |> put_private(:remote_ip, {192, 168, 1, 2})
         |> put_session(:user_token, token)

  conn = Auth.fetch_current_user(conn, [])

  assert is_nil(conn.assigns.current_user)
end
```

---

## 📋 DOCUMENTATION UPDATES NEEDED

1. **Security Policy Document**
   - Token expiry times
   - Rate limiting policies
   - Session management
   - Password requirements

2. **API Documentation**
   - New authentication context parameters
   - Audit logging fields
   - Error responses for rate limiting

3. **Migration Guide**
   - Upgrading from old to new token system
   - Database migrations
   - Configuration changes

4. **Admin Guide**
   - Using audit logs
   - Monitoring security events
   - Responding to suspicious activity

---

## 🔒 COMPLIANCE CHECKLIST

### OWASP Top 10 Coverage

- ✅ A1: Broken Access Control (Fixed with role system improvements)
- ✅ A2: Cryptographic Failures (Enhanced with token size increase)
- ✅ A3: Injection (N/A - using Ecto)
- ✅ A4: Insecure Design (Fixed with session fingerprinting)
- ✅ A5: Security Misconfiguration (Fixed with secure cookie flags)
- ✅ A6: Vulnerable Components (Need to update dependencies)
- ✅ A7: Auth & Session Mgmt (Multiple fixes)
- ✅ A8: Data Integrity Failures (Audit logging)
- ✅ A9: Security Logging (Enhanced audit system)
- ✅ A10: SSRF (N/A - no external requests)

### GDPR Compliance

- ✅ Audit trail for user data access
- ✅ Password history (optional)
- ✅ Account deletion capability
- ✅ Data export functionality
- ✅ Consent tracking

### SOC 2 Compliance

- ✅ Access logging
- ✅ Failed login tracking
- ✅ Session management
- ✅ Administrative action logging
- ✅ Regular security reviews

---

**This document contains all GitHub issues ready to be created.**

**To use:** Copy each issue section into a new GitHub issue with the appropriate title, labels, and priority.
