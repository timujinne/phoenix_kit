# Security Policy

## Overview

PhoenixKit takes security seriously. This document outlines the security features, best practices, and vulnerability reporting procedures for the project.

## Security Features

### Authentication Security

#### 1. Password Security

- **Bcrypt Hashing**: All passwords are hashed using bcrypt before storage
- **Minimum Length**: Passwords must be at least 8 characters
- **Maximum Length**: Limited to 72 bytes to prevent DoS attacks
- **No Plain Text Storage**: Password field is virtual and never persisted
- **Session Invalidation**: All sessions are invalidated on password change

**Implementation**: `lib/phoenix_kit/users/auth/user.ex`

#### 2. Rate Limiting

PhoenixKit implements comprehensive rate limiting to prevent brute-force and DoS attacks:

| Endpoint | Limit | Window | Strategy |
|----------|-------|--------|----------|
| Login (`POST /users/log-in`) | 5 attempts | 1 minute | Per IP |
| Password Reset (`POST /users/forgot-password`) | 3 requests | 5 minutes | Per IP |
| Magic Link (`POST /users/magic-link`) | 3 requests | 1 minute | Per IP |

**Configuration**:
```elixir
# config/config.exs
config :hammer,
  backend: {Hammer.Backend.ETS, [
    expiry_ms: 60_000 * 60 * 2,
    cleanup_interval_ms: 60_000 * 10
  ]}
```

**Implementation**:
- `lib/phoenix_kit_web/plugs/rate_limiter.ex` - Rate limiting plug
- `lib/phoenix_kit_web/users/session.ex:25-33` - Login rate limiting
- `lib/phoenix_kit_web/users/forgot_password.ex:31-56` - Password reset rate limiting
- `lib/phoenix_kit_web/users/magic_link.ex:68-94` - Magic link rate limiting

**Disable Rate Limiting** (for testing):
```elixir
PhoenixKit.Settings.set_setting("auth_rate_limiting_enabled", "false")
```

#### 3. Timing Attack Protection

PhoenixKit prevents user enumeration through timing attacks:

**Login Protection** (`lib/phoenix_kit/users/auth/user.ex:226-229`):
```elixir
def valid_password?(_, _) do
  Bcrypt.no_user_verify()  # Simulates password check for non-existent users
  false
end
```

**Password Reset Protection** (`lib/phoenix_kit_web/users/forgot_password.ex:98-108`):
- Async processing prevents timing analysis
- Fake token generation for non-existent users
- Simulated email sending delay (50-150ms)
- Generic success message regardless of user existence

**Magic Link Protection** (`lib/phoenix_kit_web/users/magic_link.ex:150-159`):
- Similar async processing and delay simulation
- Prevents determining valid email addresses

#### 4. Token Security

**Password Reset Tokens**:
- SHA256 hashing before database storage
- 32 bytes of cryptographic randomness
- 24-hour expiry period
- Single-use (automatically deleted after use)
- Email verification (tokens invalidated if email changes)

**Magic Link Tokens**:
- SHA256 hashing before database storage
- 15-minute expiry period (configurable)
- Single-use tokens
- Automatic revocation of old tokens on new request

**Session Tokens**:
- 60-day validity period
- Automatic cleanup of expired tokens
- Can be revoked individually or in bulk

**Implementation**: `lib/phoenix_kit/users/auth/user_token.ex`

#### 5. Automatic Token Cleanup

Expired tokens are automatically cleaned up daily at 2 AM via Oban cron job:

```elixir
# config/config.exs
config :phoenix_kit, Oban,
  plugins: [
    {Oban.Plugins.Cron,
     crontab: [
       {"0 2 * * *", PhoenixKit.Workers.TokenCleanupWorker, args: %{}}
     ]}
  ]
```

**Manual Cleanup**:
```elixir
# Clean up all expired tokens
PhoenixKit.Workers.TokenCleanupWorker.perform(%{})

# Clean up specific token types
PhoenixKit.Workers.TokenCleanupWorker.cleanup_password_reset_tokens()
PhoenixKit.Workers.TokenCleanupWorker.cleanup_magic_link_tokens()

# Get token statistics
PhoenixKit.Workers.TokenCleanupWorker.get_token_stats()
```

**Implementation**: `lib/phoenix_kit/workers/token_cleanup_worker.ex`

### Email Security

- **Email Confirmation**: Prevents unauthorized account creation
- **Email Change Verification**: Requires confirmation for email updates
- **Token-based Verification**: All email operations use secure tokens

### Session Security

- **Session Renewal**: Sessions renewed on login/logout to prevent fixation
- **Remember Me**: Optional persistent sessions
- **Multiple Device Support**: Users can have sessions across devices
- **Session Invalidation**: Admin can force logout from all devices

### User Enumeration Prevention

PhoenixKit prevents attackers from determining valid email addresses:

1. **Generic Error Messages**: "Invalid email or password" (not "Email not found")
2. **Consistent Timing**: Same response time for valid/invalid emails
3. **Generic Success Messages**: "If your email is in our system, you will receive..."
4. **Rate Limiting**: Prevents bulk email validation attempts
5. **Logging**: All auth attempts logged for security monitoring

## Security Best Practices

### For Developers

1. **Always Hash Passwords**:
```elixir
# ❌ BAD
user = %User{password: "plaintext"}

# ✅ GOOD
{:ok, user} = Auth.register_user(%{email: email, password: password})
```

2. **Use Provided Auth Functions**:
```elixir
# ✅ GOOD
case Auth.get_user_by_email_and_password(email, password) do
  %User{} = user -> # Login successful
  nil -> # Invalid credentials
end
```

3. **Check Session Validity**:
```elixir
# ✅ GOOD
user = Auth.get_user_by_session_token(token)
```

4. **Invalidate Sessions on Security Changes**:
```elixir
# ✅ GOOD - After password reset
Auth.delete_all_user_session_tokens(user)
```

### For Applications Using PhoenixKit

1. **Enable HTTPS in Production**:
```elixir
# config/prod.exs
config :my_app, MyAppWeb.Endpoint,
  force_ssl: [rewrite_on: :x_forwarded_proto]
```

2. **Configure Secure Headers**:
```elixir
# In your endpoint.ex
plug :put_secure_browser_headers, %{
  "x-frame-options" => "DENY",
  "x-content-type-options" => "nosniff",
  "referrer-policy" => "strict-origin-when-cross-origin"
}
```

3. **Use Environment Variables for Secrets**:
```elixir
# config/runtime.exs
config :my_app, MyApp.Repo,
  password: System.get_env("DATABASE_PASSWORD")
```

4. **Configure Rate Limiting for Production**:
```elixir
# For multi-node deployments, use Redis backend
config :hammer,
  backend: {Hammer.Backend.Redis, [
    expiry_ms: 60_000 * 60 * 4,
    redis_url: System.get_env("REDIS_URL")
  ]}
```

5. **Monitor Rate Limit Violations**:
```elixir
# Set up logging/alerting for rate limit events
# All violations are logged with event: "rate_limit_violation"
```

## Monitoring and Logging

PhoenixKit logs all security-relevant events:

```elixir
# Login attempts
Logger.info("Successful login", user_id: user.id, email: email)
Logger.warning("Failed login - invalid password", email: email)

# Rate limit violations
Logger.warning("Rate limit exceeded",
  identifier: ip_address,
  rate_limit_key: "auth:login",
  event: "rate_limit_violation"
)

# Password reset requests
Logger.info("Password reset email sent", email: email)
Logger.info("Password reset requested for non-existent email", email: email)

# Token cleanup
Logger.info("Token cleanup completed",
  total_deleted: 523,
  password_reset: 12,
  magic_link: 456
)
```

### Recommended Monitoring Queries

```elixir
# Detect brute-force attacks
grep "rate_limit_violation" logs/ | grep "auth:login"

# Monitor password reset abuse
grep "Password reset" logs/ | grep "rate limit exceeded"

# Track token cleanup efficiency
grep "Token cleanup completed" logs/
```

## Vulnerability Reporting

If you discover a security vulnerability in PhoenixKit, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. Email security concerns to: [security@beamlab.eu]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Updates

Security patches are released as soon as possible after verification. Always use the latest version of PhoenixKit:

```elixir
# In mix.exs
{:phoenix_kit, "~> 1.5"}
```

Check for updates:
```bash
mix hex.outdated phoenix_kit
```

## Security Checklist

Before deploying to production, verify:

- [ ] HTTPS enabled with valid SSL certificate
- [ ] Secure session cookies configured
- [ ] Rate limiting enabled (`auth_rate_limiting_enabled: true`)
- [ ] Token cleanup job scheduled
- [ ] Database backups configured
- [ ] Security headers configured
- [ ] Logging and monitoring enabled
- [ ] Secrets stored in environment variables (not config files)
- [ ] Latest PhoenixKit version installed
- [ ] Dependencies up to date (`mix hex.outdated`)
- [ ] CSRF protection enabled (Phoenix default)
- [ ] XSS protection enabled (Phoenix default)

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Phoenix Security Guide](https://hexdocs.pm/phoenix/security.html)
- [Elixir Security](https://elixir-lang.org/blog/2024/01/18/security-practices/)
- [Hammer Rate Limiting](https://hexdocs.pm/hammer/readme.html)

## License

This security policy is part of PhoenixKit and is licensed under MIT.

---

**Last Updated**: 2025-11-15
**Version**: 1.5.2
