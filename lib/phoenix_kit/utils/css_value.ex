defmodule PhoenixKit.Utils.CssValue do
  @moduledoc """
  Allowlist validation for operator-supplied values that are embedded in CSS.

  A settings field that ends up inside a stylesheet is not ordinary text: the
  surrounding `<style>` element is parsed as raw character data, so HTML
  escaping does not apply there and a value carrying `</style>` closes the
  element and starts a new one. That turned the auth-page background colour —
  a free-text field reachable by any holder of the `settings` permission — into
  stored XSS served to every anonymous visitor of the login page.

  Both functions here are **allowlists that fail to `""`**, not sanitisers that
  attempt repair. A value that is not recognisably a colour or a URL is dropped
  entirely, because guessing at what an unrecognised value meant is how
  filters get bypassed.

  ## Usage

      iex> PhoenixKit.Utils.CssValue.color("#1e293b")
      "#1e293b"

      iex> PhoenixKit.Utils.CssValue.color("linear-gradient(135deg, #667eea 0%, #764ba2 100%)")
      "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"

      iex> PhoenixKit.Utils.CssValue.color("red; } </style><script>alert(1)</script>")
      ""

      iex> PhoenixKit.Utils.CssValue.url("/file/018e/original/ab12")
      "/file/018e/original/ab12"

      iex> PhoenixKit.Utils.CssValue.url("x'); } </style><script>alert(1)</script>")
      ""
  """

  # Colours, colour functions and gradients need letters, digits, `#`, `%`,
  # `.`, `,`, `-`, parentheses and spaces — and nothing else. Excluding every
  # other character is what makes the result structurally unable to leave the
  # declaration it sits in: `;`, `{`, `}`, `<`, `>`, quotes, backslash and `/`
  # (so no `/*` comment either) simply cannot appear.
  #
  # A literal space, not `\s`: a newline cannot break out of a declaration on
  # its own, but nothing legitimate needs one here, and keeping control
  # characters out of a value that is written into a page served to anonymous
  # visitors costs nothing.
  @color_charset ~r/^[a-zA-Z0-9#%.,() -]+$/

  # `url(` and `expression(` are spellable within that charset and are the two
  # constructs that reach the network or (historically) an evaluator from
  # inside a declaration, so they are refused by name.
  @color_forbidden ~r/url\s*\(|expression\s*\(/i

  # A generous ceiling: real colours and gradients are far shorter, and an
  # unbounded value in a page served to anonymous visitors is its own problem.
  @max_length 256

  # Characters legal in a URL that also cannot terminate the `url('…')` token
  # or the surrounding element. Quotes, parentheses, backslash, whitespace,
  # `<` and `>` are all excluded.
  @url_charset ~r|^[A-Za-z0-9._~:/?\#\[\]@!$&*+,;=%-]+$|

  @doc """
  Returns `value` when it is a safe CSS colour, colour function or gradient,
  otherwise `""`.

  Accepts what the background-colour setting is actually for — hex colours,
  `rgb()` / `rgba()` / `hsl()` / `hsla()`, CSS named colours, and
  `linear-gradient()` / `radial-gradient()` — and refuses everything else.
  """
  @spec color(term()) :: String.t()
  def color(value) when is_binary(value) do
    trimmed = String.trim(value)

    if safe_color?(trimmed), do: trimmed, else: ""
  end

  def color(_value), do: ""

  @doc """
  Returns `value` when it is safe to place inside a CSS `url('…')` token,
  otherwise `""`.

  Only same-origin absolute paths and `http`/`https` URLs are accepted. The
  application generates these from a stored file uuid, so this is a guard
  against a malformed or crafted uuid reaching the stylesheet, not against an
  operator typing a URL.
  """
  @spec url(term()) :: String.t()
  def url(value) when is_binary(value) do
    trimmed = String.trim(value)

    if safe_url?(trimmed), do: trimmed, else: ""
  end

  def url(_value), do: ""

  defp safe_color?(""), do: false

  defp safe_color?(value) do
    String.length(value) <= @max_length and
      Regex.match?(@color_charset, value) and
      not Regex.match?(@color_forbidden, value)
  end

  defp safe_url?(""), do: false

  defp safe_url?(value) do
    String.length(value) <= @max_length and
      Regex.match?(@url_charset, value) and
      absolute_or_rooted?(value)
  end

  # A rooted path (`/file/…`) or an explicit http(s) URL. A protocol-relative
  # `//host/…` is refused: it is a same-origin-looking way to point the page at
  # another host.
  defp absolute_or_rooted?("//" <> _rest), do: false
  defp absolute_or_rooted?("/" <> _rest), do: true
  defp absolute_or_rooted?("http://" <> _rest), do: true
  defp absolute_or_rooted?("https://" <> _rest), do: true
  defp absolute_or_rooted?(_value), do: false
end
