defmodule PhoenixKit.SettingsSecretPerimeterTest do
  @moduledoc """
  S015 pt.5, from external review of pt.4's mutation test: moving 8 keys from
  `@restricted_setting_keys` to `@public_setting_keys` and watching the
  round-trip tests go red only proves the tests catch a SHIFTED boundary. It
  does not prove they would have caught the actual historical failure — a key
  present in NEITHER list AND absent from `get_defaults/0` entirely, which is
  exactly how `billing_stripe_secret_key` and its siblings went unnoticed for
  as long as they did. The partition invariant in `settings_test.exs` walks
  `Settings.get_defaults/0`'s own keys; a key that was never added there is
  not merely misclassified, it is invisible to that check.

  This file has two describe blocks:

    * the first is a **permanent regression test proving the OLD limitation
      is real** — a synthetic secret-shaped key, written through the real
      write path, outside all three lists. It is expected to stay green
      forever: `get_defaults/0`-based partition was never designed to see
      keys outside `get_defaults/0`, and widening it to "every key ever
      passed to Settings.*" would fail today against dozens of legitimate
      module settings that were never meant to be classified (see
      `PhoenixKit.Test.SecretKeyPerimeter`'s moduledoc for why that's the
      wrong fix).
    * the second exercises the actual fix: a static scan of core's own
      `lib/` tree and migration seeds for secret-shaped key literals,
      asserted against `restricted_setting_keys/0`. This is the guard that
      would have caught a NEW gap of this exact shape, had the offending
      code lived inside core rather than in a separate hex package (see the
      scanner's own moduledoc for that boundary).
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries
  alias PhoenixKit.Test.SecretKeyPerimeter

  describe "the old get_defaults/0 partition invariant cannot see a key outside get_defaults/0" do
    test "a secret-shaped key absent from all three lists is written unencrypted, and the invariant still passes" do
      probe_key = "s015_perimeter_probe_totally_secret_key"

      # Fact 1: absent from every list this module exposes — not a fixture,
      # the real compiled attributes.
      refute probe_key in Settings.restricted_setting_keys()
      refute probe_key in Settings.public_setting_keys()
      refute probe_key in Map.keys(Settings.get_defaults())

      # Fact 2: the real write path (not a synthetic call — the same
      # `update_setting/2` phoenix_kit_billing itself calls) stores it
      # UNENCRYPTED, because `maybe_encrypt_restricted_value/1` only
      # consults `restricted_setting_keys/0`, and this key is on neither
      # that list nor anything derived from it.
      {:ok, _} = Settings.update_setting(probe_key, "totally-secret-probe-value")

      raw = Queries.get_setting_by_key(probe_key)

      refute String.starts_with?(raw.value, "enc:v1:"),
             "expected the probe to be stored in the clear — proving the gap, not the fix"

      assert raw.value == "totally-secret-probe-value"

      # Fact 3: the EXACT assertion `settings_test.exs`'s "every get_defaults/0
      # key is classified exactly once" test makes — reproduced here, not
      # imported, so this test does not silently start passing/failing
      # because that OTHER test changed shape — still holds. The probe key
      # never entered `all_keys` (it never touched get_defaults/0), so it
      # cannot show up as "missing from the partition" no matter how secret
      # it looks or how plainly it sits in the database.
      all_keys = Settings.get_defaults() |> Map.keys() |> Enum.sort()

      classified =
        (Settings.public_setting_keys() ++ Settings.restricted_setting_keys())
        |> Enum.sort()

      assert classified == all_keys,
             "if this fails, get_defaults/0 drifted from the two lists for an unrelated " <>
               "reason — that is a real bug, but not the one this test documents"

      refute probe_key in all_keys
    end
  end

  describe "core-owned secret-key perimeter guard (S015 pt.5)" do
    # The real scan, against this checkout's actual lib/ tree and migrations —
    # the surface a FUTURE core-introduced secret (a new migration seed, a new
    # single-key Settings call with a literal secret-shaped name) would have
    # to cross. Whatever this finds today is expected to already be on
    # restricted_setting_keys/0 — S015 pt.4 already closed every case this
    # scan can see; this test exists to keep it closed, not to find something
    # new right now.
    test "every secret-shaped key literal core's own source references or seeds is restricted" do
      root = File.cwd!()

      found =
        (SecretKeyPerimeter.scan_settings_literals(Path.join(root, "lib")) ++
           SecretKeyPerimeter.scan_migration_seed_literals(Path.join(root, "lib")))
        |> Enum.uniq()

      secret_shaped = Enum.filter(found, &SecretKeyPerimeter.secret_shaped?/1)

      # Sanity floor: if this drops to zero, the scan itself broke (wrong
      # root, regex stopped matching after an unrelated refactor) rather than
      # core having gotten cleaner — a scan that finds nothing and a scan
      # that works are indistinguishable without this.
      assert "aws_secret_access_key" in secret_shaped,
             "the scan should at least find aws_secret_access_key (lib/modules/storage " <>
               "reads it via a literal Settings.get_setting call) — if it did not, the " <>
               "scan itself is broken, not the classification"

      for key <- secret_shaped do
        assert key in Settings.restricted_setting_keys(),
               "#{key} looks like it carries live credential material (core's own source " <>
                 "references or seeds it) but is not on @restricted_setting_keys"
      end
    end

    # Mutation, safely: a fixture file the scanner has never seen before,
    # containing exactly the shape of gap this guard exists for (a literal,
    # single-key Settings call naming a secret-shaped key that is nowhere
    # classified) — proving the SCAN MECHANISM finds it, without touching a
    # real production file to do it. The real end-to-end mutation (add the
    # same shape to an actual lib/ file, watch the test above go red, restore
    # via a pre-mutation copy — never `git checkout`) is recorded, with its
    # actual output, in S015-evidence.md; this test is what stays in the
    # suite afterward, small and fast enough to run on every future PR.
    test "the scan is not vacuous: it finds a secret-shaped key in a planted fixture" do
      tmp_root =
        Path.join(
          System.tmp_dir!(),
          "s015_perimeter_fixture_#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(tmp_root)
      on_exit(fn -> File.rm_rf!(tmp_root) end)

      File.write!(Path.join(tmp_root, "planted_module.ex"), """
      defmodule PlantedProbe do
        def read do
          Settings.get_setting("planted_fixture_totally_secret_key", "")
        end
      end
      """)

      found = SecretKeyPerimeter.scan_settings_literals(tmp_root)

      assert "planted_fixture_totally_secret_key" in found
      assert SecretKeyPerimeter.secret_shaped?("planted_fixture_totally_secret_key")

      # And the migration-seed scanner separately, same fixture directory,
      # different shape of gap (seeded, not called).
      File.write!(Path.join(tmp_root, "fake_migration.ex"), """
      defmodule FakeMigration do
        def up do
          execute(\"\"\"
          INSERT INTO phoenix_kit_settings ("key", "module", "value", "value_json")
          VALUES ('planted_seed_secret_key', 'fixture', 'x', NULL)
          ON CONFLICT ("key") DO NOTHING
          \"\"\")
        end
      end
      """)

      seeded = SecretKeyPerimeter.scan_migration_seed_literals(tmp_root)
      assert "planted_seed_secret_key" in seeded
      assert SecretKeyPerimeter.secret_shaped?("planted_seed_secret_key")
    end
  end
end
