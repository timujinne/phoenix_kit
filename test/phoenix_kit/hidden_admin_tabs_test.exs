defmodule PhoenixKit.HiddenAdminTabsTest do
  @moduledoc """
  "I want this module's data but not its UI" is an ordinary need — a host may
  install `phoenix_kit_locations` purely as a data layer and never want its
  admin section.

  `Registry.unregister_tab/1` looks like the answer and is a trap: it mutates
  GenServer state, and the registry rebuilds from `AdminTabs.default_tabs/0`
  every time it initialises. Any supervisor restart resurrects the hidden tab
  mid-flight with nothing to signal it. The whole point of doing this from
  config, applied at init, is that it survives the rebuild — so that is what
  these test.
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Dashboard.AdminTabs
  alias PhoenixKit.Dashboard.Registry

  setup do
    previous = Application.get_env(:phoenix_kit, :hidden_admin_tabs)

    on_exit(fn ->
      if previous do
        Application.put_env(:phoenix_kit, :hidden_admin_tabs, previous)
      else
        Application.delete_env(:phoenix_kit, :hidden_admin_tabs)
      end
    end)

    :ok
  end

  # The exact composition `load_admin_defaults_internal/0` applies on every
  # registry rebuild, which is the property that matters: it is applied at the
  # rebuild, so a restart cannot resurrect a hidden tab.
  defp rebuilt_tab_ids do
    AdminTabs.default_tabs() |> Registry.apply_hidden_admin_tabs() |> Enum.map(& &1.id)
  end

  test "a configured tab id is absent from the rebuilt set" do
    # Pick a real tab so this cannot pass by naming something that never existed.
    [%{id: target} | _] = AdminTabs.core_tabs()

    assert target in rebuilt_tab_ids()

    Application.put_env(:phoenix_kit, :hidden_admin_tabs, [target])

    refute target in rebuilt_tab_ids()
  end

  test "hiding one tab leaves the others alone" do
    [%{id: target} | rest] = AdminTabs.core_tabs()
    survivor = hd(rest).id

    Application.put_env(:phoenix_kit, :hidden_admin_tabs, [target])

    ids = rebuilt_tab_ids()
    refute target in ids
    assert survivor in ids
  end

  test "an unset config hides nothing" do
    Application.delete_env(:phoenix_kit, :hidden_admin_tabs)

    assert Registry.hidden_admin_tabs() == []
    assert rebuilt_tab_ids() != []
  end

  test "non-atom entries are ignored rather than crashing the registry" do
    # A tab id is an atom; a config typo should not take the whole admin
    # sidebar down on boot.
    Application.put_env(:phoenix_kit, :hidden_admin_tabs, ["admin_dashboard", :admin_dashboard])

    assert Registry.hidden_admin_tabs() == [:admin_dashboard]
  end
end
