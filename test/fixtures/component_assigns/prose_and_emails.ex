defmodule Fixture.Prose do
  @moduledoc false
  use Phoenix.Component

  attr(:name, :string, required: true)

  def contact(assigns) do
    ~H"""
    <p>
      Mail support@example.com or {@name}
      <img alt="ping @admin here" src="x.png" />
    </p>
    """
  end
end
