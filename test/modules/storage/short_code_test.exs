defmodule PhoenixKit.Modules.Storage.ShortCodeTest do
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.ShortCode
  alias PhoenixKit.Users.Auth

  defp file!(owner) do
    n = System.unique_integer([:positive])

    {:ok, file} =
      Storage.create_file(%{
        original_file_name: "c#{n}.png",
        file_name: "c#{n}.png",
        file_path: "x/c#{n}.png",
        mime_type: "image/png",
        file_type: "image",
        ext: "png",
        file_checksum: Ecto.UUID.generate(),
        user_file_checksum: Ecto.UUID.generate(),
        size: 1,
        status: "active",
        user_uuid: owner.uuid
      })

    file
  end

  setup do
    {:ok, owner} =
      Auth.register_user(%{
        "email" => "code-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    %{owner: owner}
  end

  describe "generate/0" do
    test "is 8 characters of base58, without the look-alikes" do
      for _ <- 1..500 do
        code = ShortCode.generate()
        assert ShortCode.valid?(code)
        assert code =~ ~r/\A[1-9A-HJ-NP-Za-km-z]{8}\z/
        refute code =~ ~r/[0OIl]/
      end
    end

    test "does not repeat itself" do
      codes = for _ <- 1..2000, do: ShortCode.generate()
      assert length(Enum.uniq(codes)) == length(codes)
    end

    test "uses the whole alphabet, not a slice of it" do
      chars =
        for _ <- 1..400, c <- String.graphemes(ShortCode.generate()), into: MapSet.new(), do: c

      assert MapSet.size(chars) == 58
    end
  end

  describe "valid?/1" do
    test "accepts a code and nothing else" do
      assert ShortCode.valid?("k3Fq9xA2")
      refute ShortCode.valid?("k3Fq9xA")
      refute ShortCode.valid?("k3Fq9xA22")
      refute ShortCode.valid?("k3Fq9xA0")
      refute ShortCode.valid?("k3Fq9xAl")
      refute ShortCode.valid?("k3Fq9x A")
      refute ShortCode.valid?(nil)
      refute ShortCode.valid?(12_345_678)
    end
  end

  describe "a file" do
    test "gets a code when it is made, and is found by it", %{owner: owner} do
      file = file!(owner)
      assert ShortCode.valid?(file.short_code)
      assert Storage.get_file_by_short_code(file.short_code).uuid == file.uuid
    end

    test "two files have two codes", %{owner: owner} do
      assert file!(owner).short_code != file!(owner).short_code
    end

    test "keeps its code when it is changed", %{owner: owner} do
      file = file!(owner)
      {:ok, changed} = Storage.update_file(file, %{original_file_name: "renamed.png"})
      assert changed.short_code == file.short_code
    end

    test "a code cannot be set through attrs", %{owner: owner} do
      file = file!(owner)
      {:ok, changed} = Storage.update_file(file, %{short_code: "AAAAAAAA"})
      assert changed.short_code == file.short_code
    end
  end

  describe "get_file_by_short_code/1" do
    test "is nil for an unknown code, a malformed one and a non-string" do
      assert Storage.get_file_by_short_code("zzzzzzzz") == nil
      assert Storage.get_file_by_short_code("nope") == nil
      assert Storage.get_file_by_short_code(nil) == nil
    end
  end
end
