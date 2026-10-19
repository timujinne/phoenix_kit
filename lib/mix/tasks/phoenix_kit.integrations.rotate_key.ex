defmodule Mix.Tasks.PhoenixKit.Integrations.RotateKey do
  @moduledoc """
  Rotates the encryption key protecting stored integration credentials,
  restricted `PhoenixKit.Settings` values (`oauth_*_client_secret`,
  `aws_*` — see `PhoenixKit.Settings.restricted_setting_keys/0`) AND storage
  buckets' `secret_access_key`. All are encrypted under the same resolved key,
  so all must rotate together.

  ## Usage

      $ mix phoenix_kit.integrations.rotate_key --dry-run
      $ mix phoenix_kit.integrations.rotate_key
      $ mix phoenix_kit.integrations.rotate_key --new-key="<already-generated-secret>"

  ## What it does

  1. If a key store is configured (`:integrations_key_store`), checks it can
     be written to — BEFORE touching any data. Rotation is the dangerous
     moment: once rows are re-encrypted, a store that then refuses the write
     leaves you holding a database no key opens.
  2. Reads every stored integration connection, every restricted setting
     value and every storage bucket secret.
  3. Decrypts each one under whichever key is CURRENTLY active (a
     dedicated `:integrations_encryption_key` if configured, then a
     configured key store, else the legacy `secret_key_base`-derived key —
     see `PhoenixKit.Integrations.Encryption`).
  4. If every row decrypts cleanly, re-encrypts all of them under the new
     secret in a single database transaction — either every connection
     rotates, or (on any failure) none do.
  5. Stores the new secret and **reads it back to confirm it landed** before
     reporting success. A write that returns `:ok` and did not land is the
     failure this exists to prevent.

  ## With and without a key store

  With `:integrations_key_store` configured, the secret is written there and
  the app picks it up on restart — no config edit, and the secret is not
  printed because it does not need to be. See
  `PhoenixKit.Integrations.KeyStore`; the default
  `PhoenixKit.Integrations.KeyStore.File` writes one file, mode 0600, outside
  the repository, and is per-host.

  Without one, behaviour is unchanged: the secret is printed exactly once and
  saved nowhere, with a warning saying so. You must then configure
  `integrations_encryption_key` yourself and restart.

  Migrating from an explicit key to a store is one rotation: run this with both
  set (the explicit key is what decrypts the current rows), then remove
  `integrations_encryption_key` and restart. The task says so explicitly when it
  sees both, because an explicit key outranks the store and a restart before
  removing it would read nothing.

  ## When to run this

    * **First adoption** — no dedicated key is configured yet, so every
      connection is protected only by the legacy `secret_key_base`-derived
      key. Run this once, set the printed secret, restart.
    * **Suspected key compromise** — a dedicated key is already configured.
      Run this, replace the env var with the newly printed secret, restart.
      Treat the old key as permanently compromised; do not reuse it.

  ## Options

    * `--dry-run` — runs the decrypt-and-verify pass over every row and
      reports how many WOULD rotate, without generating a key or writing
      anything. Unlike a real rotation, this does NOT take row locks —
      it's a plain read, safe to run against live traffic at any time, not
      just before committing to a real rotation.
    * `--new-key` — supply your own secret instead of generating one (e.g.
      one already stored in a secrets manager). Skipped in `--dry-run`. Must
      not be empty — `--new-key=""` is refused outright rather than
      silently falling back to a generated secret, since that's very likely
      a shell variable that resolved empty (`--new-key="$MAYBE_UNSET"`) and
      not something you meant to ask for.

  ## Run this with nothing else writing to integration connections, restricted settings or bucket keys

  A real rotation's row lock only defends against ONE direction of a race
  with a concurrent writer (an OAuth token auto-refresh, a "Test
  Connection" click, an admin saving the Authorization settings page...) —
  see `PhoenixKit.Integrations.KeyRotation`'s moduledoc, "Atomicity and
  concurrent writers", for the exact mechanism and what it does NOT cover.
  In short: a writer that already read a row before rotation locked it can
  still silently overwrite the freshly rotated row with old-key content
  after rotation commits, and `rotate/2` will have already reported
  success by then. **Pause anything that could write to integration
  connections, restricted settings or a storage bucket's own keys (most
  concretely: an OAuth token-refresh worker, the Authorization settings
  page, the bucket edit form, or moving a bucket's keys into Integrations)
  before running
  this for real, and do not resume it until you have restarted the app
  under the new key** — not just until this command returns. Treat the
  whole span, start to restart, as one maintenance window.

  ## The gap between rotating and restarting

  Rotation only changes what's in the database; the running app keeps using
  the OLD key until you set the new one and restart. This is the SAME
  maintenance window the section above requires — it doesn't end when this
  command returns, it ends when the app is running under the new key. In
  that window:

    * A storage bucket that carries its own keys (not one on an Integrations
      connection) stops working once the storage manager's bucket cache
      (5-minute TTL) reloads the rotated row: its `secret_access_key` is now
      under the new key, so the S3 credentials come back without a secret
      until the app restarts onto the new key.
    * A READ of a rotated connection does not raise or crash — a field
      that can't be decrypted under the still-active old key is logged
      and silently dropped from whatever asked for it (see
      `PhoenixKit.Integrations.Encryption`'s decrypt-failure handling),
      same as any other decrypt failure. Not an exception to catch — the
      field is simply absent.
    * A WRITE that must first read-and-merge the existing row (most writes
      in `PhoenixKit.Integrations` work this way, including fully
      automatic ones like a validation-status update after every
      token-refresh attempt) is NOT destructive just because it hits a
      row this task already rotated: it restores the untouched field's
      ciphertext before saving, as long as the write itself doesn't
      supply a fresh value for that exact field. The field stays exactly
      as rotation left it and decrypts fine again once the app restarts.
    * A WRITE that DOES supply a fresh value for that exact field is
      still at risk, whether it's this simple gap or the race the section
      above describes: whatever gets encrypted uses whichever key is
      ACTIVE, which is still the OLD one until the app restarts, so that
      value lands under the OLD key in a row this task already moved to
      the new secret. It then fails to decrypt once the app restarts onto
      the new key, indistinguishable from unrelated corruption.

  There is no dual-key fallback to paper over any of this (it would
  silently mask exactly the failure class this task exists to prevent).
  Restart promptly, and keep writers paused until you do.
  """

  use Mix.Task

  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Integrations.KeyRotation
  alias PhoenixKit.Integrations.KeyStore
  alias PhoenixKit.Integrations.KeyStore.Chain

  @shortdoc "Rotates the encryption key protecting stored integration credentials"

  @switches [dry_run: :boolean, new_key: :string]

  @impl Mix.Task
  def run(argv) do
    case parse_args(argv) do
      {:ok, opts} ->
        Mix.Task.run("app.start")
        if Keyword.get(opts, :dry_run, false), do: run_dry(), else: run_real(opts)

      {:error, message} ->
        Mix.raise(message)
    end
  end

  # Parses this task's CLI args, `{:ok, opts} | {:error, message}`. Public
  # (but undocumented, `@doc false`) and pure — `run/1` isn't itself a
  # unit-test seam (it starts the app), but this decision is — same
  # reasoning as `Mix.Tasks.PhoenixKit.Repair.exit_code/1`. Deliberately
  # `strict:` rather than `switches:`: with `switches:`, an unrecognized or
  # misspelled flag — `--dryrun` instead of `--dry-run` — is silently
  # accepted as an extra boolean under its OWN (wrong) key rather than
  # erroring, so `Keyword.get(opts, :dry_run, false)` would quietly default
  # to `false` and run a REAL rotation instead of the dry run the caller
  # typed the flag to get. `strict:` turns that same typo into a parse
  # error here instead.
  @doc false
  @spec parse_args([String.t()]) :: {:ok, keyword()} | {:error, String.t()}
  def parse_args(argv) do
    case OptionParser.parse(argv, strict: @switches) do
      {opts, _argv, []} -> validate_new_key(opts)
      {_opts, _argv, errors} -> {:error, "Invalid option(s): #{format_option_errors(errors)}"}
    end
  end

  # An explicitly empty `--new-key=""` is refused rather than silently
  # treated as "flag not passed, generate one instead". Generating and
  # using a random secret when the caller passed an EMPTY value (most
  # plausibly `--new-key="$SOME_VAR"` where the variable resolved empty) is
  # a real rotation under a key the caller never chose and that is printed
  # to stdout exactly once — if that output isn't captured, the credential
  # is unrecoverable even though the command "succeeded". Silently
  # substituting behavior for a value the caller DID supply, just wrong, is
  # the same class of surprise `strict:` above exists to prevent.
  defp validate_new_key(opts) do
    case Keyword.get(opts, :new_key) do
      "" ->
        {:error,
         "--new-key was passed but empty. Omit the flag entirely to generate a secret, or pass a real one."}

      # Refused HERE, before anything is re-encrypted. A short key used to be
      # accepted, the rows rewritten under it, and the secret reported as safely
      # stored — and then `PhoenixKit.Integrations.Encryption` rejected it as too
      # weak on the next boot and fell back to a different tier, leaving every
      # rotated row unreadable. The task must not accept a key the app will not.
      value when is_binary(value) ->
        minimum = Encryption.min_dedicated_key_length()

        if String.length(value) < minimum do
          {:error,
           "--new-key is #{String.length(value)} characters; the minimum accepted as a " <>
             "dedicated key is #{minimum}. A shorter one would be rejected on the next boot " <>
             "and every rotated row would become unreadable. Nothing was changed."}
        else
          {:ok, opts}
        end

      _ ->
        {:ok, opts}
    end
  end

  defp format_option_errors(errors) do
    Enum.map_join(errors, ", ", fn
      {flag, nil} -> flag
      {flag, value} -> "#{flag}=#{inspect(value)}"
    end)
  end

  defp run_dry do
    # A dry run only needs the decrypt-and-verify pass — the "new secret"
    # never reaches an encrypt call, so a placeholder is fine here.
    case KeyRotation.rotate("dry-run-placeholder-unused", dry_run: true) do
      {:ok, %{rotated: n}} ->
        Mix.shell().info("OK — #{n} row(s) would rotate cleanly. Nothing was written.")

      {:error, {:decrypt_failed, uuid, reason}} ->
        Mix.raise(decrypt_failed_message(uuid, reason))

      {:error, {:encryption_disabled, status}} ->
        Mix.raise(encryption_disabled_message(status))
    end
  end

  defp run_real(opts) do
    {new_secret, supplied?} = resolve_new_secret(opts)

    # Pre-flight BEFORE anything is re-encrypted. Rotation is the dangerous
    # moment: once the rows are written under the new secret, a store that then
    # refuses the write leaves an operator holding a database no key opens.
    # Checking first turns that disaster into an abort that changed nothing.
    case KeyStore.preflight() do
      :ok -> :ok
      :not_configured -> :ok
      {:error, reason} -> Mix.raise(preflight_failed_message(reason))
    end

    case KeyRotation.rotate(new_secret) do
      {:ok, %{rotated: n}} ->
        store_and_report(n, new_secret, supplied?)

      {:error, {:decrypt_failed, uuid, reason}} ->
        Mix.raise(decrypt_failed_message(uuid, reason))

      {:error, {:encryption_disabled, status}} ->
        Mix.raise(encryption_disabled_message(status))
    end
  end

  # The rows are already re-encrypted by the time this runs. Whether the secret
  # is now safe is decided here, and it is decided by reading it back — a write
  # that returned :ok and did not land is precisely the failure being guarded
  # against.
  #
  # Public for the same testability reason as `parse_args/1` and
  # `resolve_new_secret/1`: the defect a partial chain failure produces lives
  # in what gets printed and raised, and a test that cannot reach that cannot
  # guard it. Unlike those two this isn't pure (it calls `KeyStore` and
  # `Mix.shell()`), but it needs no database and no running app — only the
  # configured key store, which a test can set to a real temp-dir file store
  # beside a synthetic failing one.
  @doc false
  @spec store_and_report(non_neg_integer(), String.t(), boolean()) :: :ok
  def store_and_report(count, secret, supplied?) do
    case KeyStore.write_verified(secret) do
      :ok ->
        print_stored_success(count, KeyStore.describe())
        warn_if_explicit_key_shadows_store()

      :not_configured ->
        print_unstored_success(count, secret, supplied?)

      {:error, {:chain_write_failed, failures} = reason} ->
        case succeeded_chain_stores(failures) do
          [] ->
            print_secret_of_last_resort(secret)
            Mix.raise(store_failed_message(reason, KeyStore.describe()))

          succeeded ->
            print_secret_partially_stored(secret, succeeded)
            Mix.raise(chain_partial_failure_message(reason, succeeded))
        end

      {:error, reason} ->
        print_secret_of_last_resort(secret)
        Mix.raise(store_failed_message(reason, KeyStore.describe()))
    end
  end

  # Which configured chain members are NOT in `failures` — i.e. wrote the
  # secret successfully. `failures` (from `{:chain_write_failed, failures}`)
  # only ever lists what went wrong; it says nothing about what went right,
  # and the messages below must not call a secret "the only copy" when a
  # member of the very chain that just partially failed is already holding it.
  @spec succeeded_chain_stores(list()) :: [KeyStore.configured()]
  defp succeeded_chain_stores(failures) do
    case KeyStore.configured() do
      {Chain, opts} ->
        failed_modules = Enum.map(failures, fn {module, _result} -> module end)

        opts
        |> Chain.stores()
        |> Enum.reject(fn {module, _store_opts} -> module in failed_modules end)

      _ ->
        []
    end
  end

  defp describe_stores(stores) do
    Enum.map_join(stores, ", and ", fn {module, store_opts} ->
      case KeyStore.invoke_store(module, :describe, [store_opts]) do
        location when is_binary(location) -> location
        _ -> inspect(module)
      end
    end)
  end

  # Resolves the secret a real (non-dry-run) rotation writes under:
  # `{secret, supplied?}`. Trusts `opts` came through `parse_args/1`, which
  # already rejects an explicitly-empty `--new-key=""` (see
  # `validate_new_key/1`) — so `nil` here means the flag was genuinely never
  # passed, not "passed but empty", and generating a secret is unambiguously
  # correct. Public for the same testability reason as `parse_args/1`.
  @doc false
  @spec resolve_new_secret(keyword()) :: {String.t(), boolean()}
  def resolve_new_secret(opts) do
    case Keyword.get(opts, :new_key) do
      value when is_binary(value) -> {value, true}
      nil -> {generate_secret(), false}
    end
  end

  defp decrypt_failed_message(uuid, reason) do
    "Row #{uuid} (an integration connection or restricted setting in phoenix_kit_settings, " <>
      "or a bucket in phoenix_kit_buckets) failed to decrypt under the CURRENTLY active key " <>
      "(#{inspect(reason)}). " <>
      "Rotation aborted — NOTHING was written, not even for rows that decrypted fine. " <>
      "Investigate this row (it may already be encrypted under a different key from an " <>
      "earlier partial change, or genuinely corrupted) before retrying."
  end

  defp encryption_disabled_message(status) do
    "Refusing to rotate — encryption is not active (status: #{inspect(status)}). " <>
      "Rotation re-encrypts under a new secret; with no key active there is nothing " <>
      "meaningful to rotate. Set integration_encryption_enabled: true and configure a key " <>
      "first."
  end

  defp generate_secret, do: 32 |> :crypto.strong_rand_bytes() |> Base.encode64()

  defp print_stored_success(count, location) do
    Mix.shell().info("""

    Rotated #{count} row(s) (integration connections, restricted settings and/or bucket secrets).

    The new secret was written to #{location} and read back to confirm it landed.
    On this host there is nothing else to copy: PhoenixKit reads the key from there.

    If you run more than one host, note that the default file store is per-host:
    every node needs this same secret at that path (or a shared one) before it is
    restarted, or it will keep using its old key and write rows nothing else can read.

    Restart the app to pick it up. Stored connections are encrypted under the NEW
    secret, so reads fail until the restart — don't delay between the two.
    """)
  end

  defp print_unstored_success(count, secret, supplied?) do
    Mix.shell().info("\nRotated #{count} row(s).\n")

    unless supplied? do
      Mix.shell().info("""
      New secret (shown ONCE — copy it now, THIS TASK SAVED IT NOWHERE):

          #{secret}

      No key store is configured, so nothing on this machine now holds this
      secret. Lose this line and every stored integration credential becomes
      unreadable: the ciphertext stays in the database and no key opens it.

      To have future rotations save the key for you:

          config :phoenix_kit, integrations_key_store: PhoenixKit.Integrations.KeyStore.File

      That writes one file, mode 0600, outside the repository.
      """)
    end

    Mix.shell().info("""
    Set it as the active key and restart the app, e.g. in runtime.exs:

        config :phoenix_kit, integrations_encryption_key: System.get_env("PHOENIX_KIT_INTEGRATIONS_ENCRYPTION_KEY")

    #{wired_secret_reference(supplied?)} Stored connections are now
    encrypted under the NEW secret — reads will fail until you configure it and restart,
    so don't delay between running this and restarting.
    """)
  end

  # `--new-key` skips the "printed above" block entirely (see `supplied?`
  # above) — the operator already has the secret they passed on the command
  # line, so this closing paragraph must not point back at output that was
  # never shown.
  @doc false
  @spec wired_secret_reference(boolean()) :: String.t()
  def wired_secret_reference(false),
    do: "with the value above wired to that environment variable."

  def wired_secret_reference(true),
    do: "with the --new-key secret you supplied wired to that environment variable."

  # Printed only when the store failed AFTER the data was re-encrypted. At that
  # point the secret on screen is the only copy in existence, so withholding it
  # to keep secrets off stdout would destroy the credentials it protects.
  defp print_secret_of_last_resort(secret) do
    Mix.shell().info("""

    The data IS already re-encrypted under this secret, and storing it FAILED.
    This line is now the only copy — save it somewhere safe before doing
    anything else:

        #{secret}
    """)
  end

  # Printed instead of `print_secret_of_last_resort/1` when the failed store
  # was one member of a chain and at least one OTHER member wrote
  # successfully. The secret is NOT "the only copy" in that case — it is
  # already saved wherever `succeeded` names — and saying otherwise both
  # overstates the danger and buries the fact that a working copy already
  # exists to fix the failed member FROM.
  defp print_secret_partially_stored(secret, succeeded) do
    Mix.shell().info("""

    The data IS already re-encrypted under this secret. It is already saved
    at #{describe_stores(succeeded)} — this is NOT the only copy — but part
    of the configured chain failed to write it (see below). Copy it to the
    failed member too before doing anything else:

        #{secret}
    """)
  end

  # An explicit `:integrations_encryption_key` outranks the store
  # (`PhoenixKit.Integrations.Encryption` resolves it first), so after this
  # rotation the app would keep using the OLD explicit key and read nothing.
  #
  # Deliberately a warning and not a refusal. Refusing was tried and is wrong:
  # migrating FROM an explicit key TO a store requires the explicit key to be
  # present during the rotation — it is what decrypts the current rows — and it
  # can only be removed afterwards. Blocking that leaves no migration path at
  # all.
  defp warn_if_explicit_key_shadows_store do
    case PhoenixKit.Config.get(:integrations_encryption_key) do
      {:ok, explicit} when is_binary(explicit) and explicit != "" ->
        Mix.shell().info("""
        ACTION REQUIRED before you restart.

        integrations_encryption_key is still set in your config, and an explicit key
        outranks the key store. If you restart now, the app will use that OLD key and
        will not read anything rotated just now.

        Remove integrations_encryption_key from your config — the store replaces it —
        and then restart.
        """)

      _ ->
        :ok
    end
  end

  defp preflight_failed_message(reason) do
    "Refusing to rotate — the configured key store is not writable (#{describe_store_error(reason)}). " <>
      "NOTHING was re-encrypted; the current key is untouched and the app keeps working. " <>
      "Fix the store and run this again."
  end

  defp store_failed_message(reason, location) do
    "Rotation succeeded but storing the new secret FAILED (#{describe_store_error(reason)}). " <>
      "The connections are already re-encrypted under the secret printed above, and " <>
      "#{location || "the store"} does not hold it. Save that secret now, then either fix the " <>
      "store and write it there, or set it as integrations_encryption_key directly."
  end

  # Unlike `store_failed_message/2`, part of the chain already holds the
  # secret — so this must not claim `location` (which, per `Chain.describe/1`,
  # names EVERY configured member, not just the failed one) "does not hold
  # it", and must not suggest shadowing the store with an explicit config key:
  # that store already has the right value, and shadowing it would just mean
  # a future restart reads the OLD key from config instead of the new one the
  # working chain member already holds.
  defp chain_partial_failure_message(reason, succeeded) do
    "Rotation succeeded, and #{describe_stores(succeeded)} already #{holds_or_hold(succeeded)} " <>
      "the new secret — but part of the key store chain FAILED to write it " <>
      "(#{describe_store_error(reason)}). Copy the secret printed above into the failed " <>
      "member too, or the chain is not the backup it looks like."
  end

  defp holds_or_hold([_one]), do: "holds"
  defp holds_or_hold(_more), do: "hold"

  # Delegates to the store's own describer, which withholds the payload of any
  # error shape it does not recognise: a host-supplied store may return a term
  # that quotes the value it failed to store, and an inspect/1 fallback would
  # copy that straight into an operator-facing message.
  defp describe_store_error(reason), do: KeyStore.describe_error(reason)
end
