defmodule PhoenixKitWeb.Components.MediaBrowserGalleryItemsTest do
  @moduledoc """
  `Helpers.gallery_items_json/2`: the window of pictures the `ViewerGallery`
  hook hands to `Fresco.gallery`. Pure data, no storage.
  """

  use ExUnit.Case, async: true

  alias PhoenixKitWeb.Components.MediaBrowser.Helpers

  defp image(n, extra \\ %{}) do
    Map.merge(
      %{
        file_uuid: "img-#{n}",
        file_type: "image",
        filename: "#{n}.jpg",
        width: 4000,
        height: 3000,
        urls: %{"small" => "/s/#{n}", "medium" => "/m/#{n}", "large" => "/l/#{n}"}
      },
      extra
    )
  end

  defp decode(json), do: Jason.decode!(json)

  test "the window is the open picture and twelve either side, index relative to it" do
    siblings = Enum.map(1..40, &image/1)

    %{"items" => items, "index" => index} = decode(Helpers.gallery_items_json(siblings, 20))

    assert length(items) == 25
    assert hd(items)["key"] == "img-9"
    assert List.last(items)["key"] == "img-33"
    assert Enum.at(items, index)["key"] == "img-21"
  end

  test "the window is cut at the ends of the list" do
    siblings = Enum.map(1..5, &image/1)

    assert %{"items" => [%{"key" => "img-1"} | _] = items, "index" => 0} =
             decode(Helpers.gallery_items_json(siblings, 0))

    assert length(items) == 5

    assert %{"index" => 4} = decode(Helpers.gallery_items_json(siblings, 4))
  end

  test "an original is drawn from the large copy, at its own size" do
    %{"items" => [item]} = decode(Helpers.gallery_items_json([image(1)], 0))

    assert %{
             "src" => "/l/1",
             "width" => 4000,
             "height" => 3000,
             "actual" => true,
             "kind" => "image",
             "rotation" => 0
           } = item
  end

  test "the large copy falls back to medium, then small" do
    no_large = image(1, %{urls: %{"small" => "/s/1", "medium" => "/m/1"}})
    only_small = image(2, %{urls: %{"small" => "/s/2"}})

    %{"items" => [a, b]} = decode(Helpers.gallery_items_json([no_large, only_small], 0))

    assert a["src"] == "/m/1"
    assert b["src"] == "/s/2"
  end

  test "a burned copy brings its own variant and extent, and is fitted" do
    burned =
      image(1, %{
        burn_size: %{variant: "burn", w: 5000, h: 3500},
        urls: %{"burn" => "/b/1", "large" => "/l/1"}
      })

    %{"items" => [item]} = decode(Helpers.gallery_items_json([burned], 0))

    assert %{"src" => "/b/1", "width" => 5000, "height" => 3500, "actual" => false} = item
  end

  test "rotation is normalised to 0..359 from an integer or a string" do
    siblings = [
      image(1, %{rotation: -90}),
      image(2, %{rotation: 450}),
      image(3, %{rotation: "180"}),
      image(4, %{rotation: "sideways"})
    ]

    %{"items" => items} = decode(Helpers.gallery_items_json(siblings, 0))

    assert Enum.map(items, & &1["rotation"]) == [270, 90, 180, 0]
  end

  test "anything that is not an image is a card with its name" do
    pdf = %{file_uuid: "doc-1", file_type: "document", filename: "plan.pdf"}
    bare = %{file_uuid: "x-1"}

    %{"items" => [a, b]} = decode(Helpers.gallery_items_json([pdf, bare], 0))

    assert a == %{"key" => "doc-1", "kind" => "document", "label" => "plan.pdf"}
    assert b == %{"key" => "x-1", "kind" => "file", "label" => ""}
  end

  test "an empty list or a bad index is an empty window" do
    assert decode(Helpers.gallery_items_json([], 0)) == %{"items" => [], "index" => 0}
    assert decode(Helpers.gallery_items_json(nil, nil)) == %{"items" => [], "index" => 0}
  end
end
