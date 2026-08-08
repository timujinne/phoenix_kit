defmodule PhoenixKit.VersionChangesTest do
  @moduledoc """
  `mix phoenix_kit.update --status` reported version numbers and "Various
  improvements and new features", which does not help anyone decide between
  upgrading now and next sprint.

  That gap is visible in this triage: several already-shipped features reached
  us as bug reports, because a host had no way to learn a capability existed
  short of reading release notes they had no reason to open.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Install.Common
  alias PhoenixKit.Migrations.Postgres

  describe "describe_version_changes/2" do
    test "names the versions being crossed instead of saying 'various improvements'" do
      target = Postgres.current_version()
      changes = Common.describe_version_changes(target - 3, target)

      refute changes =~ "Various improvements"
      assert changes =~ "V#{target}"
    end

    test "reports only the versions in the range" do
      target = Postgres.current_version()
      changes = Common.describe_version_changes(target - 1, target)

      assert changes =~ "V#{target}"
      refute changes =~ "V#{target - 1}:"
    end

    test "an up-to-date install has nothing to report" do
      target = Postgres.current_version()

      assert Common.describe_version_changes(target, target) =~ "No changes"
      assert Common.describe_version_changes(target + 1, target) =~ "No changes"
    end

    test "the LATEST marker is not carried into the output" do
      # The moduledoc marks the newest section with "⚡ LATEST" for readers of
      # the source; it is noise in a host's terminal.
      target = Postgres.current_version()

      refute Common.describe_version_changes(target - 1, target) =~ "LATEST"
    end

    test "falls back rather than crashing when nothing matches" do
      # Version 0 to 1 predates the headings convention. A diagnostic must not
      # be the reason a status check fails.
      assert is_binary(Common.describe_version_changes(0, 1))
    end
  end
end
