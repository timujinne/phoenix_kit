defmodule Fixture.ReceiverPut do
  @moduledoc false
  use Phoenix.Component

  # Map.put on a SUB-map of assigns puts nothing into assigns: @src is a
  # real KeyError. A receiver-blind key collector hid exactly this.
  attr(:user, :map, required: true)

  def avatar(assigns) do
    user = Map.put(assigns.user, :src, avatar_url(assigns.user))
    ~H"<img src={@src} alt={user.name} />"
  end

  defp avatar_url(user), do: Map.get(user, :url, "/default.png")
end
