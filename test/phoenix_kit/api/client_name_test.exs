defmodule PhoenixKit.API.ClientNameTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.API.ClientName

  describe "slug/1" do
    test "lowercases and joins the words with a dash" do
      assert ClientName.slug("Acme Print") == "acme-print"
    end

    test "romanizes a title in another script" do
      assert ClientName.slug("Декор для дома") == "dekor-dlya-doma"
    end

    test "folds accents and drops symbols" do
      assert ClientName.slug("Café Déco — Prints & Frames") =~ ~r/\Acafe-deco-prints/
    end

    test "is cut at 32 characters and never ends in a dash" do
      slug = ClientName.slug("abcdefghij abcdefghij abcdefghi xyz")

      assert slug == "abcdefghij-abcdefghij-abcdefghi"
      assert byte_size(ClientName.slug(String.duplicate("long ", 20))) <= 32
    end

    test "falls back to shop when nothing is left" do
      assert ClientName.slug("日本語") == "shop"
      assert ClientName.slug("   ") == "shop"
      assert ClientName.slug("") == "shop"
      assert ClientName.slug(nil) == "shop"
    end
  end
end
