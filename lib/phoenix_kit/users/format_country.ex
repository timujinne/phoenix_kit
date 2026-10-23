defmodule PhoenixKit.Users.FormatCountry do
  @moduledoc """
  Which country's formats a user reads: `resolve/1`.

  The first of these that names a country `BeamLabCountries` knows:

    1. the user's own `country` (a person's, or a company account's own);
    2. the `country` of the company the user belongs to (`organization_uuid`);
    3. the `registration_country` the account signed up from;
    4. the site default, Settings → General → `format_country`.

  `nil` means nothing names one, and callers fall back to what they used before
  (for dates, the site-wide `date_format` setting).

  ## The viewer

  A page is written for whoever looks at it, so the country is resolved once for
  the viewer, when the scope is mounted (`put_viewer/1`), and kept in the process
  dictionary - the same way the Gettext locale is. `PhoenixKit.Utils.Date` reads
  it (`viewer/0`) so every date a page prints follows the viewer without the
  caller passing anything. With no viewer set (a background job, a signed-out
  visitor) `viewer/0` is the site default.

  The functions of `PhoenixKit.Utils.Date` that take a user ask `for_user/1`
  instead: the user given is the one whose format is wanted, not the one in the
  process. A viewer's own record reuses the answer already resolved for them.

  A host that renders for someone other than the process's viewer calls
  `for_user/1` and passes the code on; it never has to touch the process
  dictionary.
  """

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.User

  @viewer_key :phoenix_kit_format_country

  @doc """
  The country whose formats `user` reads, as an upper-case alpha-2 code, or
  `nil`. A `nil` user (nobody signed in), or anything that is not a user row, gets the site default.
  """
  @spec resolve(User.t() | term()) :: String.t() | nil
  def resolve(%User{} = user) do
    normalize(user.country) || company_country(user) || normalize(user.registration_country) ||
      site_default()
  end

  # Nobody signed in, or something that is not a user row (a caller that
  # stands in a bare map for "no personal settings"): the site default.
  def resolve(_), do: site_default()

  @doc """
  The site default country (Settings → General), or `nil` when none is chosen.
  Read from the settings cache.
  """
  @spec site_default() :: String.t() | nil
  def site_default do
    normalize(Settings.get_setting_cached("format_country", ""))
  end

  @doc """
  `resolve/1` for a user that is not necessarily the viewer: the viewer's own
  record reuses the country already resolved for the process.
  """
  @spec for_user(User.t() | term()) :: String.t() | nil
  def for_user(%User{uuid: uuid} = user) when is_binary(uuid) do
    case Process.get(@viewer_key) do
      {:resolved, ^uuid, code} -> code
      {:pending, %User{uuid: ^uuid}} -> viewer()
      _ -> resolve(user)
    end
  end

  def for_user(user), do: resolve(user)

  @doc """
  Sets the viewer of this process. Called when a scope is mounted and again after
  the viewer saves their profile.

  The country is not looked up here: most requests never print a date, and the
  company lookup is a query. `viewer/0` resolves it the first time it is asked.
  """
  @spec put_viewer(User.t() | nil) :: :ok
  def put_viewer(user) do
    Process.put(@viewer_key, {:pending, user})
    :ok
  end

  @doc """
  The viewer's country: what `put_viewer/1` named, or the site default when
  nobody was set for this process.
  """
  @spec viewer() :: String.t() | nil
  def viewer do
    case Process.get(@viewer_key) do
      {:resolved, _uuid, code} ->
        code

      {:pending, user} ->
        code = resolve(user)
        Process.put(@viewer_key, {:resolved, user && user.uuid, code})
        code

      nil ->
        site_default()
    end
  end

  @doc "Forgets the viewer, so `viewer/0` is the site default again."
  @spec clear_viewer() :: :ok
  def clear_viewer do
    Process.delete(@viewer_key)
    :ok
  end

  @doc """
  `code` as the upper-case alpha-2 code of a country `BeamLabCountries` knows,
  else `nil`. Blank, a name instead of a code, a retired or made-up code are
  all `nil`: a bad value in one source must not stop the next from being tried.
  """
  @spec normalize(term()) :: String.t() | nil
  def normalize(code) when is_binary(code) do
    code = code |> String.trim() |> String.upcase()

    if byte_size(code) == 2 and BeamLabCountries.get(code), do: code
  end

  def normalize(_), do: nil

  # The company is another account row; read only its `country`, one primary-key
  # lookup, and only when the user has none of their own and belongs to one.
  defp company_country(%User{organization_uuid: org_uuid}) when is_binary(org_uuid) do
    query = from(u in User, where: u.uuid == ^org_uuid, select: u.country)

    normalize(RepoHelper.repo().one(query))
  rescue
    _ -> nil
  catch
    :exit, _ -> nil
  end

  defp company_country(_), do: nil
end
