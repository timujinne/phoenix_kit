defmodule PhoenixKit.Test.ModuleFixtureTables do
  @moduledoc """
  The few columns of a module's table that core's orphan-file check reads, for
  tests of that check.

  Core 3.0 creates no module table, so a test of `Storage.orphaned_files_query/1`
  that needs a module's table makes a minimal one itself. Call `create!/1` from
  the test (or its `setup`): the DDL runs in the sandbox transaction and is
  rolled back with it, so nothing is left behind. These are not the modules'
  tables — only the columns core's built-in references (and the tests' inserts)
  touch.
  """

  alias PhoenixKit.Test.Repo

  @ddl %{
    cat_catalogues: """
    CREATE TABLE phoenix_kit_cat_catalogues (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text, data jsonb NOT NULL DEFAULT '{}',
      inserted_at timestamptz, updated_at timestamptz)
    """,
    cat_categories: """
    CREATE TABLE phoenix_kit_cat_categories (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text, catalogue_uuid uuid,
      data jsonb NOT NULL DEFAULT '{}', inserted_at timestamptz, updated_at timestamptz)
    """,
    cat_items: """
    CREATE TABLE phoenix_kit_cat_items (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text, data jsonb NOT NULL DEFAULT '{}',
      inserted_at timestamptz, updated_at timestamptz)
    """,
    cat_pdfs: """
    CREATE TABLE phoenix_kit_cat_pdfs (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), file_uuid uuid, original_filename text,
      inserted_at timestamptz, updated_at timestamptz)
    """,
    post_media: """
    CREATE TABLE phoenix_kit_post_media (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), file_uuid uuid)
    """,
    entities: """
    CREATE TABLE phoenix_kit_entities (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text, display_name text,
      created_by_uuid uuid)
    """,
    entity_data: """
    CREATE TABLE phoenix_kit_entity_data (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), entity_uuid uuid, title text,
      data jsonb NOT NULL DEFAULT '{}')
    """
  }

  @doc """
  Creates the named tables in the current (sandbox) transaction.

  A database upgraded from 2.x already has the real table; it is dropped here
  and the minimal one made in its place. All of it is DDL inside the sandbox
  transaction, so the rollback puts the real table back.
  """
  @spec create!([atom()]) :: :ok
  def create!(names) do
    for name <- names do
      Repo.query!("DROP TABLE IF EXISTS phoenix_kit_#{name} CASCADE")
      Repo.query!(Map.fetch!(@ddl, name))
    end

    :ok
  end
end
