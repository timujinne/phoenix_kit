defmodule Mix.Tasks.PhoenixKit.RepairTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.PhoenixKit.Repair, as: RepairTask
  alias PhoenixKit.Migrations.ExpectedSchema.Resolver
  alias PhoenixKit.Migrations.Repair.Report

  # `run/1` itself isn't a good unit-test seam (starts the app, needs a real
  # DB) — see `Mix.Tasks.PhoenixKit.Gen.Migration.migration_content/5` for
  # the established pattern this follows: exercise the pure decision the
  # task makes from a `PhoenixKit.Migrations.Repair` result directly.

  describe "exit_code/1" do
    test "delegates to Report.exit_code/1 for a completed run" do
      report =
        Report.new("public", true, %{
          comment: 135,
          floor: 121,
          current: 151
        })

      assert RepairTask.exit_code({:ok, report}) == 0
    end

    test ":not_generated → 1 (nothing attempted, but expected today, not a failure)" do
      assert RepairTask.exit_code({:error, :not_generated}) == 1
    end

    test "every other hard error → 2" do
      assert RepairTask.exit_code({:error, {:below_floor, 90, 121}}) == 2
      assert RepairTask.exit_code({:error, {:above_current, 200, 151}}) == 2
      assert RepairTask.exit_code({:error, {:not_installed, "public"}}) == 2
      assert RepairTask.exit_code({:error, {:pooled_connection, "msg"}}) == 2
      assert RepairTask.exit_code({:error, {:concurrent_migration, 135, 142}}) == 2
    end
  end

  describe "error_tag/1 — the {:json} error object's discriminator" do
    test ":not_generated" do
      assert RepairTask.error_tag(:not_generated) == "not_generated"
    end

    test "2-tuples" do
      assert RepairTask.error_tag({:pooled_connection, "msg"}) == "pooled_connection"
      assert RepairTask.error_tag({:not_installed, "public"}) == "not_installed"
    end

    test "3-tuples" do
      assert RepairTask.error_tag({:below_floor, 90, 121}) == "below_floor"
      assert RepairTask.error_tag({:above_current, 200, 151}) == "above_current"
      assert RepairTask.error_tag({:concurrent_migration, 135, 142}) == "concurrent_migration"
    end
  end

  describe "table_of/1 — the by-table breakdown must not invent tables" do
    test "the classes whose id is table-scoped yield their table" do
      assert RepairTask.table_of(%{object_id: "table:phoenix_kit_users"}) == "phoenix_kit_users"

      assert RepairTask.table_of(%{object_id: "column:phoenix_kit_users.email"}) ==
               "phoenix_kit_users"

      assert RepairTask.table_of(%{
               object_id: "constraint:phoenix_kit_users.phoenix_kit_users_pkey"
             }) == "phoenix_kit_users"

      assert RepairTask.table_of(%{object_id: "seed:phoenix_kit_currencies:EUR"}) ==
               "phoenix_kit_currencies"
    end

    test "the classes that name the object itself are dropped, not guessed at" do
      # The regression these pin: every one of these ids "parses" under a
      # first-segment rule, so an absent index used to be tallied as a table
      # named after the index — 616 index ids against 161 real tables, each
      # inventing a one-finding row and inflating the `+N more tables` tail.
      assert RepairTask.table_of(%{object_id: "index:idx_calendar_events_owner_starts_at"}) == nil

      assert RepairTask.table_of(%{
               object_id: "sequence:phoenix_kit_warehouse_goods_issues_number_seq"
             }) == nil

      assert RepairTask.table_of(%{object_id: "function:uuid_generate_v7()"}) == nil
      assert RepairTask.table_of(%{object_id: "extension:citext"}) == nil
    end

    test "findings carrying no object_id are dropped" do
      assert RepairTask.table_of(%{object_id: nil, kind: :comment_ahead_of_schema}) == nil
      assert RepairTask.table_of(%{kind: :adopt_required}) == nil
    end

    test "every object class the manifest emits is classified deliberately" do
      # The guard that keeps this honest: a class added to the manifest without
      # a decision here silently rejoins the "invents a table" branch, which is
      # unobservable from the report itself.
      case Resolver.resolve() do
        {:error, :not_generated} ->
          assert true

        {:ok, manifest} ->
          classes =
            "public"
            |> manifest.objects()
            |> MapSet.new(fn %{id: id} -> hd(String.split(id, ":", parts: 2)) end)

          assert MapSet.equal?(
                   classes,
                   MapSet.new(~w(table column constraint seed index sequence function extension))
                 ),
                 "manifest object classes changed to #{inspect(Enum.sort(classes))} — " <>
                   "decide in table_of/1 whether each new class's id is table-scoped"
      end
    end
  end
end
