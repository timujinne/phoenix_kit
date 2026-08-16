defmodule Fixture.Commented do
  @moduledoc false
  use Phoenix.Component

  attr(:real, :string, required: true)

  def doc(assigns) do
    ~H"""
    <div>
      <%!-- shows {@ghost} when ready --%>
      <!-- and {@other} -->
      {@real}
    </div>
    """
  end
end
