defmodule PhoenixKit.Integration.ModuleOwnedManifestTest do
  @moduledoc """
  An object the core chain creates but a module owns is not in core's
  `ExpectedSchema` manifest, so `mix phoenix_kit.doctor`/`repair` neither
  check its shape nor put it back.

  The case: V135 creates `fk_newsletters_broadcasts_template`
  (`template_uuid` → `phoenix_kit_email_templates`), and the newsletters
  module repoints it, under the same name, at a table of its own. While core's
  manifest described the FK, `verify` reported such an install as
  `:wrong_shape`, and on an install where the FK was gone `repair` re-created
  it pointing at the email templates table.

  Since core 3.0 the chain no longer creates the broadcasts table or its FK at
  all (the newsletters chain does), so the cases that put the FK in a state and
  ran `verify`/`repair` over it went; the manifest check stays.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.ExpectedSchema

  @table "phoenix_kit_newsletters_broadcasts"
  @fk "fk_newsletters_broadcasts_template"
  @id "constraint:#{@table}.#{@fk}"

  test "the manifest does not describe the FK, under its id or its name" do
    objects = ExpectedSchema.objects("public")

    refute Enum.any?(objects, &(&1.id == @id))
    refute Enum.any?(objects, &match?(%{check: {:catalog, %{name: @fk}}}, &1))
  end
end
