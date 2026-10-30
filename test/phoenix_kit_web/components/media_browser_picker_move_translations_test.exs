defmodule PhoenixKitWeb.Components.MediaBrowserPickerMoveTranslationsTest do
  @moduledoc """
  The picker's move says "Nothing to move" in every shipped language.
  """
  use ExUnit.Case, async: true

  @locales ~w(de es et fr it pl ru uk)

  test "the message is translated in every language" do
    for locale <- @locales do
      text =
        Gettext.with_locale(PhoenixKitWeb.Gettext, locale, fn ->
          Gettext.gettext(PhoenixKitWeb.Gettext, "Nothing to move")
        end)

      assert text != "Nothing to move", locale
    end
  end
end
