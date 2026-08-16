defmodule Fixture.UnaryMinus do
  @moduledoc false
  use Phoenix.Component

  # `-@amount` is a real read; an operator before the @ must not hide it.
  attr(:title, :string, required: true)

  def refund(assigns) do
    ~H"<span>{@title} {-@amount}</span>"
  end
end
