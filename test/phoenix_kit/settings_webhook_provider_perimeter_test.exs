defmodule PhoenixKit.SettingsWebhookProviderPerimeterTest do
  @moduledoc """
  S015 pt.6: `billing_paypal_webhook_secret` was missing from
  `@restricted_setting_keys` despite pt.4's audit and pt.5's static perimeter
  guard, because `PhoenixKitBilling.Web.WebhookController.get_webhook_secret/1`
  builds the key by STRING INTERPOLATION —
  `"billing_\#{provider}_webhook_secret"` — never as a literal. Both pt.4's
  manual grep and pt.5's `SecretKeyPerimeter.scan_settings_literals/1` look
  for literal string arguments; a call site with a variable is invisible to
  either, regardless of how constant that variable's value turns out to be
  at every call site that actually exists.

  A hand-maintained list of providers (`~w(stripe paypal razorpay)`) would
  fix today's instance and repeat the exact mistake for provider #4 — this
  test resolves providers from the `handle_webhook(conn, :provider, ...)`
  call sites in `phoenix_kit_billing`'s own controller instead, so a new
  provider wired into that family fails this test the moment it's added,
  without anyone remembering to update a list here.

  `:everypay` is deliberately NOT expected here: `WebhookController.everypay/2`
  never calls `handle_webhook/3` — EveryPay v4 callbacks are unsigned, so
  that handler re-fetches the authoritative payment record from EveryPay's
  API instead of trusting a webhook secret at all.
  `billing_everypay_webhook_secret` does not exist anywhere (no reader, no
  writer) and this test must not invent a requirement for it.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Test.SecretKeyPerimeter

  # This is the one function in SecretKeyPerimeter that reaches outside
  # core's own repository on purpose (see its doc) — the interpolation that
  # hides `billing_paypal_webhook_secret` from a core-only scan is exactly
  # what makes that necessary. PHOENIX_KIT_BILLING_PATH lets this run against
  # an arbitrary checkout (mirrors the PHOENIX_KIT_PATH convention the
  # workspace already uses in the other direction — a module pointing at a
  # local core); unset falls back to this container's known sibling layout.
  #
  # Deliberately no existence check here or at the call site: an absent,
  # moved, or renamed directory must fail this test via the same floor
  # assertions that catch a broken scan, not skip it silently. An earlier
  # version of this test special-cased "directory not found" into an
  # `IO.puts` skip that still reported the test as passing — a plain clone
  # of core alone would have gone quietly green having checked nothing,
  # exactly the "filter stopped matching, both sides collapsed, stayed
  # green" failure this whole file exists to catch, just moved one level
  # up. Verified by running: pointing this at a nonexistent path now fails
  # the same way pointing it at an empty existing one does.
  defp billing_repo_path do
    System.get_env("PHOENIX_KIT_BILLING_PATH") || "/root/projects/phoenix_kit_billing"
  end

  describe "webhook-secret key family resolved from real call sites (S015 pt.6)" do
    test "every provider handle_webhook/3 is called with has a restricted billing_<provider>_webhook_secret" do
      root = billing_repo_path()

      # No `File.dir?(root)` branch on purpose: a silent skip when the
      # directory is absent is the SAME disease as a check that passes on an
      # empty result — the directory moving, the path being renamed, or the
      # controller being restructured all collapse to "found nothing" here,
      # and this must fail exactly like "found nothing because the scan
      # broke" does. `Path.wildcard/1` against a nonexistent root simply
      # yields no files (no error), so `providers` is `[]` and the floor
      # assertions below fail loudly instead of a passing test that checked
      # nothing. Verified by running: pointed at both an empty EXISTING
      # directory and a NONEXISTENT path, both turn this test red.
      providers = SecretKeyPerimeter.scan_webhook_provider_atoms(root) |> Enum.sort()

      # Sanity floor: if this list came back empty or missing a provider
      # known to be wired in today, the SCAN broke (wrong root, the
      # controller got refactored to a different call shape, the sibling
      # checkout moved) — not proof the family shrank. Failing loudly here
      # beats a vacuous pass.
      assert "stripe" in providers,
             "expected to find WebhookController.stripe/2's handle_webhook(conn, :stripe, ...) " <>
               "call at #{root} — if not, either the scan broke or #{root} isn't the real " <>
               "phoenix_kit_billing checkout (set PHOENIX_KIT_BILLING_PATH)"

      assert "razorpay" in providers,
             "expected to find WebhookController.razorpay/2's handle_webhook(conn, :razorpay, ...) " <>
               "call — if not, the scan itself is broken"

      assert "paypal" in providers,
             "expected to find WebhookController.paypal/2's handle_webhook(conn, :paypal, ...) " <>
               "call — if not, the scan itself is broken"

      # everypay must NOT appear — it has its own callback path that never
      # calls handle_webhook/3 (see moduledoc). If this starts failing, a
      # real everypay webhook-secret key was wired in and belongs on
      # @restricted_setting_keys, not silently accepted here.
      refute "everypay" in providers,
             "everypay now calls handle_webhook/3 — billing_everypay_webhook_secret is a real " <>
               "key now and belongs on @restricted_setting_keys, not just this assertion"

      for provider <- providers do
        key = "billing_#{provider}_webhook_secret"

        assert key in Settings.restricted_setting_keys(),
               "#{key} is read by WebhookController.get_webhook_secret(:#{provider}) " <>
                 "(handle_webhook(conn, :#{provider}, ...) call site found) but is not on " <>
                 "@restricted_setting_keys"
      end
    end

    # Mutation, safely: a fixture the scanner has never seen, containing
    # exactly the call shape this guard exists for — proving the MECHANISM
    # finds a handle_webhook(conn, :provider, ...) call site, independent of
    # whether phoenix_kit_billing happens to be checked out on this machine.
    test "the call-site scan is not vacuous: it finds a planted handle_webhook/3 call" do
      tmp_root =
        Path.join(
          System.tmp_dir!(),
          "s015_webhook_fixture_#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(tmp_root)
      on_exit(fn -> File.rm_rf!(tmp_root) end)

      File.write!(Path.join(tmp_root, "planted_controller.ex"), """
      defmodule PlantedWebhookController do
        def newprovider(conn, _params) do
          handle_webhook(conn, :newprovider, "newprovider-signature")
        end
      end
      """)

      found = SecretKeyPerimeter.scan_webhook_provider_atoms(tmp_root)

      assert "newprovider" in found
    end
  end
end
