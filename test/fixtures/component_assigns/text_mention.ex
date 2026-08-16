defmodule Fixture.TextMention do
  @moduledoc false
  use Phoenix.Component

  # An @-mention in a bare text node is prose. HEEx renders it literally;
  # flagging it is the false positive that gets a guard deleted.
  attr(:name, :string, required: true)

  def share(assigns) do
    ~H"""
    <p>Share with @marketing or {@name}</p>
    """
  end
end
