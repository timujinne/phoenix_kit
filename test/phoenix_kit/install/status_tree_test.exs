defmodule PhoenixKit.Install.StatusTreeTest do
  use ExUnit.Case, async: true

  doctest PhoenixKit.Install.StatusTree

  alias PhoenixKit.Install.StatusTree

  describe "render/2" do
    test "renders a flat tree with the last row closing it" do
      assert StatusTree.render([
               {"Installed", "V159"},
               {"Database", "Connected"},
               {"Next", "Ready"}
             ]) ==
               """
               ├── Installed: V159
               ├── Database: Connected
               └── Next: Ready\
               """
    end

    test "children of a middle row keep the continuation bar" do
      output =
        StatusTree.render([
          {"Database", "Connected"},
          {"Modules", "2 modules", ["Boards: V01", "Inbox: V01 → V02"]},
          {"Next", "Ready"}
        ])

      assert output ==
               """
               ├── Database: Connected
               ├── Modules: 2 modules
               │   ├── Boards: V01
               │   └── Inbox: V01 → V02
               └── Next: Ready\
               """
    end

    test "children of the last row use blank indentation, not a dangling bar" do
      output = StatusTree.render([{"Modules", "1 module", ["Inbox: V01"]}])

      assert output ==
               """
               └── Modules: 1 module
                   └── Inbox: V01\
               """
    end

    test "a row with an empty child list renders as a plain row" do
      assert StatusTree.render([{"Modules", "none", []}]) == "└── Modules: none"
    end

    test "a single child is closed, not branched" do
      output = StatusTree.render([{"A", "1", ["only"]}, {"B", "2"}])

      assert output =~ "│   └── only"
      refute output =~ "├── only"
    end

    test "no rows renders nothing" do
      assert StatusTree.render([]) == ""
    end

    test "label_format decorates only labels, never values or children" do
      output =
        StatusTree.render([{"Modules", "2 modules", ["Inbox: V01"]}],
          label_format: &"<#{&1}>"
        )

      assert output =~ "└── <Modules>: 2 modules"
      assert output =~ "    └── Inbox: V01"
      refute output =~ "<Inbox"
    end

    test "output carries no trailing newline — the caller owns that" do
      refute String.ends_with?(StatusTree.render([{"A", "1"}]), "\n")
    end
  end
end
