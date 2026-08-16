defmodule Fixture.CssAtRules do
  @moduledoc false
  use Phoenix.Component

  # Inline <style> is raw character data to HEEx: at-rules like @keyframes
  # and @container are prose, and even {@x} / #{@x} stay LITERAL there — the
  # one thing that interpolates inside <style> is <%= ... %>, which is how
  # this tree injects dynamic CSS. So @brand is a real read; @ignored is not.
  attr(:accent, :string, required: true)

  def styled(assigns) do
    ~H"""
    <style>
      @keyframes pk-reveal {
        from { opacity: 0; }
      }
      @container (max-height: 26px) {
        .pk-frame { display: none; }
      }
      .pk-frame { color: #{@ignored}; }
      :root { --brand: <%= @brand %>; }
    </style>
    <div class="pk-frame">{@accent}</div>
    """
  end
end
