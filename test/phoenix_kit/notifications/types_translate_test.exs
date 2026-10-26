defmodule PhoenixKit.Notifications.TypesTranslateTest do
  # Not async: it puts a module into the registry's persistent_term list.
  use ExUnit.Case, async: false

  alias PhoenixKit.Notifications.Types

  defmodule Backend do
    @moduledoc false
    use Gettext.Backend, otp_app: :phoenix_kit, priv: "test/support/no_such_gettext"

    # No catalogue: answer every lookup with a marker, so the test sees which
    # backend a label went through.
    def handle_missing_translation(_locale, _domain, _ctx, msgid, _bindings),
      do: {:ok, "[mod] " <> msgid}
  end

  defmodule Contributor do
    @moduledoc false
    def notification_types do
      [
        %{
          key: "workshop",
          label: "Workshop",
          description: "Jobs in the workshop",
          gettext_backend: Backend,
          actions: [],
          sub_types: [%{key: "cuts", label: "Cuts", actions: ["workshop.cut"]}]
        }
      ]
    end
  end

  setup do
    key = {PhoenixKit, :registered_modules}
    before = :persistent_term.get(key, :none)
    current = if before == :none, do: [], else: before
    :persistent_term.put(key, [Contributor | current])

    on_exit(fn ->
      if before == :none, do: :persistent_term.erase(key), else: :persistent_term.put(key, before)
    end)
  end

  test "core's own labels show in the reader's locale" do
    security = Enum.find(Types.list(), &(&1.key == "security"))

    Gettext.with_locale("et", fn ->
      assert Types.translate(security, :label) == "Turvalisus"
    end)

    assert Types.translate(security, :label) == "Security"
  end

  test "a module's labels go through the backend it names, and its sub-types inherit it" do
    workshop = Enum.find(Types.list(), &(&1.key == "workshop"))

    assert Types.translate(workshop, :label) == "[mod] Workshop"
    assert Types.translate(workshop, :description) == "[mod] Jobs in the workshop"
    assert [cuts] = workshop.sub_types
    assert Types.translate(cuts, :label) == "[mod] Cuts"
  end

  test "empty text stays empty; a broken backend falls back to the text" do
    assert Types.translate(%{label: ""}, :label) == ""
    assert Types.translate(%{label: "Plain", gettext_backend: NoSuchBackend}, :label) == "Plain"
  end
end
