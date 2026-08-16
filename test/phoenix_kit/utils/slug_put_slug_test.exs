defmodule PhoenixKit.Utils.SlugPutSlugTest do
  @moduledoc """
  `put_slug/3` probes the database, so these run against a real table rather than a
  mock — the scoping and self-exclusion clauses are SQL, and a mock would assert the
  query I wrote rather than the rows it actually matches.

  The table is scratch-built per test, shaped like the schemas that will adopt this
  (`uuid` primary key, `user_uuid` scope column), so a failure cannot damage anything
  real. Same pattern as the V167 integration test.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Utils.Slug

  defmodule Doc do
    @moduledoc false
    use Ecto.Schema

    @primary_key {:uuid, Ecto.UUID, autogenerate: true}
    schema "phoenix_kit_zz_put_slug" do
      field(:title, :string)
      field(:slug, :string)
      field(:user_uuid, Ecto.UUID)
      field(:code, :string)
    end

    def changeset(doc, attrs) do
      Ecto.Changeset.cast(doc, attrs, [:title, :slug, :user_uuid, :code])
    end
  end

  setup do
    Repo.query!("DROP TABLE IF EXISTS phoenix_kit_zz_put_slug")

    Repo.query!("""
    CREATE TABLE phoenix_kit_zz_put_slug (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      title character varying(255),
      slug character varying(255),
      user_uuid uuid,
      code character varying(255)
    )
    """)

    on_exit(fn ->
      PhoenixKit.RepoHelper.repo().query!("DROP TABLE IF EXISTS phoenix_kit_zz_put_slug")
    end)

    :ok
  end

  defp insert!(attrs) do
    Repo.insert!(Ecto.Changeset.change(%Doc{}, attrs))
  end

  defp slug(changeset), do: Ecto.Changeset.get_field(changeset, :slug)

  describe "put_slug/3 — which save regenerates" do
    test "generates from the source on insert" do
      changeset = Doc.changeset(%Doc{}, %{title: "Geometric Planter"})
      assert slug(Slug.put_slug(changeset, :title)) == "geometric-planter"
    end

    test "an explicit non-blank slug wins over the source" do
      changeset = Doc.changeset(%Doc{}, %{title: "Geometric Planter", slug: "hand-picked"})
      assert slug(Slug.put_slug(changeset, :title)) == "hand-picked"
    end

    test "an explicitly blanked slug regenerates from the source" do
      doc = insert!(%{title: "Old", slug: "old"})
      changeset = Doc.changeset(doc, %{title: "Brand New", slug: ""})
      assert slug(Slug.put_slug(changeset, :title)) == "brand-new"
    end

    test "a save carrying no slug leaves a stored slug alone even when the title changes" do
      # The whole point. Under `get_change/2` this returned "brand-new" and moved a
      # live URL on every ordinary edit.
      doc = insert!(%{title: "Old Title", slug: "hand-picked"})
      changeset = Doc.changeset(doc, %{title: "Brand New Title"})

      result = Slug.put_slug(changeset, :title)
      assert Ecto.Changeset.get_change(result, :slug) == nil
      assert slug(result) == "hand-picked"
    end

    test "a stored record with no slug gets one" do
      doc = insert!(%{title: "Needs One", slug: nil})
      changeset = Doc.changeset(doc, %{})
      assert slug(Slug.put_slug(changeset, :title)) == "needs-one"
    end

    test "an unromanizable source leaves the changeset untouched rather than storing a blank" do
      changeset = Doc.changeset(%Doc{}, %{title: "日本"})
      assert Ecto.Changeset.get_change(Slug.put_slug(changeset, :title), :slug) == nil
    end

    test "a missing source leaves the changeset untouched" do
      changeset = Doc.changeset(%Doc{}, %{})
      assert Ecto.Changeset.get_change(Slug.put_slug(changeset, :title), :slug) == nil
    end
  end

  describe "put_slug/3 — uniqueness" do
    test "suffixes past every taken candidate" do
      insert!(%{slug: "planter"})
      insert!(%{slug: "planter-2"})

      changeset = Doc.changeset(%Doc{}, %{title: "Planter"})
      assert slug(Slug.put_slug(changeset, :title)) == "planter-3"
    end

    test "the row being saved is excluded from its own probe" do
      # Without the self-exclusion this renames "planter" to "planter-2" on the
      # save that was only meant to blank-and-regenerate it.
      doc = insert!(%{title: "Planter", slug: "planter"})
      changeset = Doc.changeset(doc, %{slug: ""})
      assert slug(Slug.put_slug(changeset, :title)) == "planter"
    end

    test "unique: false skips the probe" do
      insert!(%{slug: "planter"})
      changeset = Doc.changeset(%Doc{}, %{title: "Planter"})
      assert slug(Slug.put_slug(changeset, :title, unique: false)) == "planter"
    end
  end

  describe "put_slug/3 — scoped uniqueness" do
    test "the same slug is free for a different scope value" do
      alice = Ecto.UUID.generate()
      bob = Ecto.UUID.generate()
      insert!(%{slug: "notes", user_uuid: alice})

      changeset = Doc.changeset(%Doc{}, %{title: "Notes", user_uuid: bob})
      assert slug(Slug.put_slug(changeset, :title, scope: [:user_uuid])) == "notes"
    end

    test "the same slug is taken within one scope value" do
      alice = Ecto.UUID.generate()
      insert!(%{slug: "notes", user_uuid: alice})

      changeset = Doc.changeset(%Doc{}, %{title: "Notes", user_uuid: alice})
      assert slug(Slug.put_slug(changeset, :title, scope: [:user_uuid])) == "notes-2"
    end

    test "a nil scope matches IS NULL rather than reporting everything free" do
      insert!(%{slug: "notes", user_uuid: nil})

      changeset = Doc.changeset(%Doc{}, %{title: "Notes"})
      assert slug(Slug.put_slug(changeset, :title, scope: [:user_uuid])) == "notes-2"
    end

    test "without :scope the probe is global and ignores the scope column" do
      insert!(%{slug: "notes", user_uuid: Ecto.UUID.generate()})

      changeset = Doc.changeset(%Doc{}, %{title: "Notes", user_uuid: Ecto.UUID.generate()})
      assert slug(Slug.put_slug(changeset, :title)) == "notes-2"
    end
  end

  describe "put_slug/3 — options" do
    test ":to writes to a field other than :slug" do
      changeset =
        Doc.changeset(%Doc{}, %{title: "Geometric Planter"})
        |> Slug.put_slug(:title, to: :code, unique: false)

      assert Ecto.Changeset.get_change(changeset, :code) == "geometric-planter"
      # ...and leaves :slug alone, so the two are independent.
      assert Ecto.Changeset.get_change(changeset, :slug) == nil
    end

    test ":locale reaches slugify" do
      changeset = Doc.changeset(%Doc{}, %{title: "Größe"})
      assert slug(Slug.put_slug(changeset, :title, locale: "de", unique: false)) == "groesse"
    end

    test ":max_length is respected by the suffix, not just the base" do
      # Regression: the suffix used to be appended after the cap, so a 20-char
      # base came back 22 chars and silently blew the ceiling — and against a
      # varchar(n) column Postgres raises rather than truncating.
      insert!(%{slug: "geometric-planter-wi"})

      changeset = Doc.changeset(%Doc{}, %{title: "Geometric Planter With A Long Tail"})
      result = slug(Slug.put_slug(changeset, :title, max_length: 20))

      assert String.length(result) <= 20
      assert String.ends_with?(result, "-2")
      refute result =~ "--"
    end

    test ":queryable narrows what counts as taken" do
      import Ecto.Query

      insert!(%{slug: "planter", title: "ignored"})

      changeset = Doc.changeset(%Doc{}, %{title: "Planter"})

      # Probe a source that excludes the conflicting row: the slug reads as free.
      queryable = from(d in Doc, where: d.title != "ignored")
      assert slug(Slug.put_slug(changeset, :title, queryable: queryable)) == "planter"
    end
  end
end
