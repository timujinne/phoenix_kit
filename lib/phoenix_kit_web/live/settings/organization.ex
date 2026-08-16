defmodule PhoenixKitWeb.Live.Settings.Organization do
  @moduledoc """
  Organization settings management LiveView for PhoenixKit.

  Provides a unified interface for company information shared between
  Legal and Billing modules. This includes company details and bank information.
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.PubSub.Manager, as: PubSubManager
  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.CountryData
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKit.Utils.Routes

  @default_company_info %{
    "name" => "",
    "address_line1" => "",
    "address_line2" => "",
    "city" => "",
    "state" => "",
    "postal_code" => "",
    "country" => "",
    "vat_number" => "",
    "registration_number" => ""
  }

  @default_bank_details %{
    "bank_name" => "",
    "iban" => "",
    "swift" => ""
  }

  def mount(_params, _session, socket) do
    # Subscribe to organization settings updates for real-time sync
    if connected?(socket) do
      PubSubManager.subscribe("organization:settings")
    end

    project_title = Settings.get_project_title()

    socket =
      socket
      |> assign(:page_title, gettext("Organization Settings"))
      |> assign(:project_title, project_title)
      |> assign(:current_path, get_current_path(socket.assigns.current_locale_base))
      |> load_settings()

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  defp load_settings(socket) do
    company_info = get_company_info()
    bank_details = get_bank_details()

    socket
    |> assign_company_info(company_info)
    |> assign_country_data(company_info["country"])
    |> assign_tax_settings(company_info)
    |> assign_bank_details(bank_details)
    |> assign(:site_url, Settings.get_setting("site_url", ""))
  end

  defp assign_company_info(socket, info) do
    socket
    |> assign(:company_name, info["name"] || "")
    |> assign(:company_vat, info["vat_number"] || "")
    |> assign(:company_registration, info["registration_number"] || "")
    |> assign(:company_address_line1, info["address_line1"] || "")
    |> assign(:company_address_line2, info["address_line2"] || "")
    |> assign(:company_city, info["city"] || "")
    |> assign(:company_state, info["state"] || "")
    |> assign(:company_postal_code, info["postal_code"] || "")
    |> assign(:company_country, info["country"] || "")
  end

  defp assign_country_data(socket, country) do
    socket
    |> assign(:countries, CountryData.countries_for_select())
    |> assign(:subdivision_label, get_subdivision_label(country))
    |> assign(:eu_country, eu_country?(country))
    |> assign_main_countries(stored_main_countries(), country)
  end

  defp stored_main_countries do
    "country_select_priority"
    |> Settings.get_setting_cached("")
    |> CountryData.parse_priority()
    |> CountryData.known_country_codes()
  end

  # Everything the card renders is precomputed here rather than called from
  # the template: a `defp` invoked from HEEX cannot be verified by the
  # compiler. `:main_country_suggestion` is what the host's own country
  # proposes and is deliberately empty once every suggested code is already
  # in the list — there is nothing left to offer.
  defp assign_main_countries(socket, codes, country) do
    chosen = MapSet.new(codes)

    socket
    |> assign(:main_countries, codes)
    |> assign(:main_country_rows, main_country_rows(codes))
    |> assign(
      :main_country_options,
      # `priority: []` on purpose: the picker is where you go to CHANGE the
      # pinned set, so it must not itself be reordered by it — otherwise the
      # first thing the dropdown offers is whatever is already pinned.
      Enum.reject(CountryData.countries_for_select(priority: []), fn {_label, code} ->
        MapSet.member?(chosen, code)
      end)
    )
    |> assign(:main_country_suggestion, main_country_suggestion(country, chosen))
  end

  defp main_country_rows(codes) do
    last = length(codes) - 1

    codes
    |> Enum.with_index()
    |> Enum.map(fn {code, index} ->
      %{
        code: code,
        label: country_label(code),
        first?: index == 0,
        last?: index == last
      }
    end)
  end

  defp main_country_suggestion(country, chosen) do
    country
    |> CountryData.suggested_priority()
    |> Enum.reject(&MapSet.member?(chosen, &1))
    |> Enum.map(fn code -> %{code: code, label: country_label(code)} end)
  end

  # Same shape as CountryData's own select entries — flag, space, localized
  # name — and defensive about the flag for the same reason its `select_entry/2`
  # is: the struct field is nilable and blank on some rows in other datasets,
  # and `nil <> " "` is an ArgumentError that would take the whole settings
  # page down. Every one of beamlab_countries 1.1.0's 250 rows carries a flag,
  # so this is about not depending on that.
  defp country_label(code) do
    name = CountryData.get_country_name(code) || code

    case CountryData.get_flag(code) do
      nil -> name
      "" -> name
      flag -> flag <> " " <> name
    end
  end

  defp assign_tax_settings(socket, _company_info) do
    tax_config = CountryData.get_tax_config()
    country = socket.assigns.company_country

    suggested_rate =
      if country != "" do
        rate = CountryData.get_standard_vat_percent(country)
        current = parse_tax_rate(tax_config.rate)
        if rate != 0 and rate != current, do: rate
      end

    socket
    |> assign(:tax_enabled, tax_config.enabled)
    |> assign(:tax_rate, tax_config.rate)
    |> assign(:suggested_tax_rate, suggested_rate)
  end

  defp assign_bank_details(socket, details) do
    socket
    |> assign(:bank_name, details["bank_name"] || "")
    |> assign(:bank_iban, details["iban"] || "")
    |> assign(:bank_swift, details["swift"] || "")
  end

  # ===================================
  # EVENT HANDLERS
  # ===================================

  def handle_event("country_changed", %{"company_country" => country_code}, socket) do
    # Update suggested tax rate when country changes
    current_rate = parse_tax_rate(socket.assigns.tax_rate)

    suggested_rate =
      if country_code != "" do
        rate = CountryData.get_standard_vat_percent(country_code)
        if rate != 0 and rate != current_rate, do: rate
      end

    # The main-countries suggestion is derived from the company country too,
    # so it goes stale the same way the tax rate would if left alone: an
    # unsaved country pick must not leave the previous country's neighbours
    # on screen.
    suggestion =
      main_country_suggestion(country_code, MapSet.new(socket.assigns.main_countries))

    {:noreply,
     socket
     |> assign(:company_country, country_code)
     |> assign(:subdivision_label, get_subdivision_label(country_code))
     |> assign(:eu_country, eu_country?(country_code))
     |> assign(:suggested_tax_rate, suggested_rate)
     |> assign(:main_country_suggestion, suggestion)}
  end

  def handle_event("save_company", params, socket) do
    data = extract_company_data(params)

    case validate_company_data(data) do
      [] ->
        save_company_info(data, params)

        # Broadcast to all admin sessions
        broadcast_settings_change(:company_info_updated)

        {:noreply,
         socket
         |> load_settings()
         |> put_flash(:info, gettext("Organization information saved"))}

      errors ->
        {:noreply, put_flash(socket, :error, Enum.join(errors, ". "))}
    end
  end

  # The main-countries card writes on every action rather than behind a save
  # button: each click is already a deliberate edit, and there is no second
  # field whose validation could hold the list hostage.
  def handle_event("add_main_country", %{"code" => code}, socket) when is_binary(code) do
    {:noreply, put_main_countries(socket, socket.assigns.main_countries ++ [code])}
  end

  def handle_event("add_main_country", _params, socket), do: {:noreply, socket}

  def handle_event("remove_main_country", %{"code" => code}, socket) do
    {:noreply,
     put_main_countries(socket, Enum.reject(socket.assigns.main_countries, &(&1 == code)))}
  end

  def handle_event("remove_main_country", _params, socket), do: {:noreply, socket}

  # SortableGrid pushes the full order on drop, so the list is taken as given
  # rather than diffed — but only codes that were already pinned are honoured,
  # so a forged payload can neither add a country nor drop one silently.
  def handle_event("reorder_main_countries", %{"ordered_ids" => ordered}, socket)
      when is_list(ordered) do
    current = socket.assigns.main_countries
    reordered = Enum.filter(ordered, &(&1 in current))
    codes = reordered ++ (current -- reordered)

    {:noreply, put_main_countries(socket, codes)}
  end

  def handle_event("reorder_main_countries", _params, socket), do: {:noreply, socket}

  # Restored alongside drag: SortableJS is a CDN fetch that a strict CSP or
  # an offline deploy can block, and dragging itself has no keyboard path —
  # without these buttons a keyboard/screen-reader operator could not
  # reorder at all.
  def handle_event("move_main_country", %{"code" => code, "direction" => direction}, socket)
      when is_binary(code) and direction in ["up", "down"] do
    {:noreply, put_main_countries(socket, move(socket.assigns.main_countries, code, direction))}
  end

  def handle_event("move_main_country", _params, socket), do: {:noreply, socket}

  def handle_event("apply_main_country_suggestion", _params, socket) do
    suggested = Enum.map(socket.assigns.main_country_suggestion, & &1.code)

    {:noreply, put_main_countries(socket, socket.assigns.main_countries ++ suggested)}
  end

  def handle_event("save_tax", params, socket) do
    tax_enabled = params["tax_enabled"] == "true"
    tax_rate = (params["tax_rate"] || "0") |> String.trim()

    # Save tax settings into company_info JSON
    company_info = get_company_info()

    updated_info =
      company_info
      |> Map.put("tax_enabled", tax_enabled)
      |> Map.put("tax_rate", tax_rate)

    Settings.update_json_setting("company_info", updated_info)

    # Also sync to legacy keys for backward compatibility with Billing/Shop
    Settings.update_setting(
      "billing_tax_enabled",
      if(tax_enabled, do: "true", else: "false")
    )

    Settings.update_setting("billing_default_tax_rate", tax_rate)
    Settings.update_setting("shop_tax_enabled", if(tax_enabled, do: "true", else: "false"))
    Settings.update_setting("shop_tax_rate", tax_rate)

    broadcast_settings_change(:tax_settings_updated)

    {:noreply,
     socket
     |> load_settings()
     |> put_flash(:info, gettext("Tax settings saved"))}
  end

  def handle_event("tax_rate_changed", %{"tax_rate" => tax_rate}, socket) do
    current_rate = parse_tax_rate(tax_rate)
    country_code = socket.assigns.company_country

    suggested_rate =
      if country_code != "" do
        rate = CountryData.get_standard_vat_percent(country_code)
        if rate != 0 and rate != current_rate, do: rate
      end

    {:noreply,
     socket
     |> assign(:tax_rate, tax_rate)
     |> assign(:suggested_tax_rate, suggested_rate)}
  end

  def handle_event("apply_suggested_tax", _params, socket) do
    case socket.assigns.suggested_tax_rate do
      nil ->
        {:noreply, socket}

      rate ->
        {:noreply,
         socket
         |> assign(:tax_rate, to_string(rate))
         |> assign(:suggested_tax_rate, nil)}
    end
  end

  def handle_event("save_bank", params, socket) do
    iban = (params["bank_iban"] || "") |> String.trim()
    swift = (params["bank_swift"] || "") |> String.trim()
    country_code = socket.assigns.company_country

    errors =
      []
      |> validate_bank_iban(iban, country_code)
      |> validate_bank_swift(swift)

    case errors do
      [] ->
        save_bank_details(params, iban, swift)

        # Broadcast to all admin sessions
        broadcast_settings_change(:bank_details_updated)

        {:noreply,
         socket
         |> load_settings()
         |> put_flash(:info, gettext("Bank details saved"))}

      errors ->
        {:noreply, put_flash(socket, :error, Enum.join(Enum.reverse(errors), ". "))}
    end
  end

  # Handle PubSub messages for settings sync
  def handle_info({:organization_settings_changed, _data}, socket) do
    {:noreply, load_settings(socket)}
  end

  # ===================================
  # DATA ACCESS (with fallback to legacy keys)
  # ===================================

  @doc """
  Gets company info from consolidated key with fallback to legacy keys.
  """
  def get_company_info do
    Map.merge(@default_company_info, CountryData.get_company_info())
  end

  @doc """
  Gets bank details from consolidated key with fallback to legacy keys.
  """
  def get_bank_details do
    Map.merge(@default_bank_details, CountryData.get_bank_details())
  end

  # ===================================
  # VALIDATION
  # ===================================

  defp extract_company_data(params) do
    %{
      name: (params["company_name"] || "") |> String.trim(),
      country: params["company_country"] || "",
      vat: (params["company_vat"] || "") |> String.trim(),
      address_line1: (params["company_address_line1"] || "") |> String.trim(),
      city: (params["company_city"] || "") |> String.trim()
    }
  end

  defp validate_company_data(data) do
    []
    |> validate_required(data.name, gettext("Company name is required"))
    |> validate_required(data.country, gettext("Country is required"))
    |> validate_required(data.vat, gettext("VAT number is required"))
    |> validate_required(data.address_line1, gettext("Street address is required"))
    |> validate_required(data.city, gettext("City is required"))
    |> validate_eu_vat(data.vat, data.country)
    |> Enum.reverse()
  end

  defp validate_required(errors, "", message), do: [message | errors]
  defp validate_required(errors, _value, _message), do: errors

  defp validate_eu_vat(errors, vat, country) when vat != "" and country != "" do
    if eu_country?(country) do
      if Regex.match?(~r/^[A-Z]{2}[0-9A-Z]{2,12}$/, String.upcase(vat)) do
        errors
      else
        [
          gettext("VAT number must be in EU format (e.g., %{country}123456789)", country: country)
          | errors
        ]
      end
    else
      errors
    end
  end

  defp validate_eu_vat(errors, _vat, _country), do: errors

  defp validate_bank_iban(errors, iban, country_code) do
    case CountryData.validate_iban_format(iban, country_code) do
      :ok -> errors
      {:error, msg} -> [msg | errors]
    end
  end

  defp validate_bank_swift(errors, swift) do
    case CountryData.validate_swift_format(swift) do
      :ok -> errors
      {:error, msg} -> [msg | errors]
    end
  end

  # ===================================
  # SAVE OPERATIONS
  # ===================================

  defp save_company_info(data, params) do
    # Merge with existing company_info to preserve tax_enabled/tax_rate keys
    existing = get_company_info()

    company_info =
      Map.merge(existing, %{
        "name" => data.name,
        "address_line1" => data.address_line1,
        "address_line2" => (params["company_address_line2"] || "") |> String.trim(),
        "city" => data.city,
        "state" => (params["company_state"] || "") |> String.trim(),
        "postal_code" => (params["company_postal_code"] || "") |> String.trim(),
        "country" => data.country,
        "vat_number" => String.upcase(data.vat),
        "registration_number" => (params["company_registration"] || "") |> String.trim()
      })

    Settings.update_json_setting("company_info", company_info)
  end

  # Only real, deduplicated country codes ever reach the setting: the card
  # offers a picker over the country list, so there is no free text to
  # sanitize, and `known_country_codes/1` is the belt-and-braces guard on a
  # forged phx-value. An empty list means nothing is pinned and every country
  # list is plain alphabetical — the setting is the only source, there is no
  # config underneath it.
  defp put_main_countries(socket, codes) do
    codes =
      codes
      |> Enum.map(&String.upcase/1)
      |> Enum.uniq()
      |> CountryData.known_country_codes()

    if codes == socket.assigns.main_countries do
      # Nothing actually changed (e.g. "Add" with an empty selection, or
      # removing/reordering into the same set) — don't write an identical
      # value and don't broadcast a no-op.
      socket
    else
      case Settings.update_setting("country_select_priority", Enum.join(codes, ", ")) do
        {:ok, _setting} ->
          # Broadcast to all admin sessions, same mechanism the other cards
          # use. `handle_info` only calls `load_settings/1` — it never
          # broadcasts itself — so the acting session's own bounce-back
          # cannot loop; it just reloads with the value already written.
          broadcast_settings_change(:main_countries_updated)

          socket
          # The Company card's country <.select> is computed once in
          # `load_settings/1`; without recomputing it here it keeps
          # offering the pre-pin alphabetical order until the next reload.
          |> assign(:countries, CountryData.countries_for_select())
          |> assign_main_countries(codes, socket.assigns.company_country)

        {:error, _changeset} ->
          put_flash(socket, :error, gettext("Main countries could not be saved"))
      end
    end
  end

  defp move(codes, code, direction) do
    case Enum.find_index(codes, &(&1 == code)) do
      nil -> codes
      index -> swap(codes, index, target_index(index, direction, length(codes)))
    end
  end

  defp target_index(index, "up", _length), do: max(index - 1, 0)
  defp target_index(index, "down", length), do: min(index + 1, length - 1)
  defp target_index(index, _direction, _length), do: index

  defp swap(codes, index, index), do: codes

  defp swap(codes, from, to) do
    moved = Enum.at(codes, from)

    codes
    |> List.delete_at(from)
    |> List.insert_at(to, moved)
  end

  defp save_bank_details(params, iban, swift) do
    bank_details = %{
      "bank_name" => (params["bank_name"] || "") |> String.trim(),
      "iban" => normalize_iban(iban),
      "swift" => String.upcase(swift)
    }

    Settings.update_json_setting("company_bank_details", bank_details)
  end

  defp normalize_iban(iban) do
    iban |> String.replace(~r/\s/, "") |> String.upcase()
  end

  # ===================================
  # HELPERS
  # ===================================

  defp get_subdivision_label(nil), do: gettext("State/Province")
  defp get_subdivision_label(""), do: gettext("State/Province")

  defp get_subdivision_label(country_code) do
    CountryData.get_subdivision_label(country_code)
  end

  defp eu_country?(nil), do: false
  defp eu_country?(""), do: false
  defp eu_country?(country_code), do: CountryData.eu_member?(country_code)

  defp parse_tax_rate(rate) when is_binary(rate) do
    case Float.parse(rate) do
      {value, _} -> if value == trunc(value), do: trunc(value), else: value
      :error -> 0
    end
  end

  defp parse_tax_rate(_), do: 0

  defp get_current_path(locale) do
    Routes.path("/admin/settings/organization", locale: locale)
  end

  # Broadcast settings change to all connected admin sessions
  defp broadcast_settings_change(type) do
    PubSubManager.broadcast(
      "organization:settings",
      {:organization_settings_changed, %{type: type, timestamp: UtilsDate.utc_now()}}
    )
  rescue
    # PubSub may not be available in all environments
    _ -> :ok
  end
end
