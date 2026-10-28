defmodule PhoenixKit.Migrations.Postgres.V164Test do
  @moduledoc """
  Pins that the chain reaches V164. (The slug-index checks on the publishing and
  subscription tables moved to those modules' chains in core 3.0: core no longer
  creates the tables.)

  V164.up/down can't be invoked outside an `Ecto.Migrator` runner (they
  rely on `Ecto.Migration.execute/1`, which checks for a runner process)
  — same constraint as V163Test/V162Test/etc. The schema is verified at
  boot instead: `test_helper.exs` runs `ensure_current/2` (now through
  V164) before any test, so the assertions below pin the post-V164 shape.
  This suite runs against the default (`public`) schema, where V164 is a
  no-op on top of an already-correct `V135` baseline in a properly
  regenerated chain — the assertions exist to catch a regression in
  either V164 itself or in a future baseline regeneration that
  reintroduces the named-schema shape as the default.
  """

  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Test.Repo

  describe "version marker" do
    test "phoenix_kit table comment is at or past V164" do
      %{rows: [[comment]]} =
        Repo.query!("SELECT obj_description('phoenix_kit'::regclass, 'pg_class')")

      # >= rather than ==: pinning the exact latest version breaks this
      # test every time a newer migration ships. What V164 owns is "the
      # chain reached at least me".
      assert String.to_integer(comment) >= 164
    end
  end
end
