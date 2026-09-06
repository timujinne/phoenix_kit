defmodule PhoenixKitWeb.Live.Settings.Users do
  @moduledoc """
  User-related settings management LiveView for PhoenixKit.

  Consolidates user configuration including:
  - Registration settings
  - New user defaults (role and status)
  - Custom user fields management
  """
  use PhoenixKitWeb, :live_view

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.CustomFields
  alias PhoenixKit.Users.CustomFields.Events, as: CustomFieldsEvents

  def mount(_params, _session, socket) do
    # Set locale for LiveView process

    # Load current settings. S007: this page never renders the OAuth login
    # secrets or AWS keys, so it has no reason to hold their real values in
    # socket state — list_public_settings/0 (an explicit allow list) leaves
    # them out entirely rather than loading and merely not rendering them.
    current_settings = Settings.list_public_settings()
    defaults = Settings.get_defaults()
    setting_options = Settings.get_setting_options()

    # Merge defaults with current settings, then take only the public keys
    # again — defaults still lists the restricted ones (harmless placeholder
    # values), and the merge must not reintroduce them.
    merged_settings =
      Map.merge(defaults, current_settings)
      |> Map.take(Settings.public_setting_keys())

    # Load custom fields
    field_definitions = CustomFields.list_field_definitions()

    # Create form changeset
    changeset = Settings.change_settings(merged_settings)

    socket =
      socket
      |> assign(:page_title, gettext("User Settings"))
      |> assign(:settings, merged_settings)
      |> assign(:saved_settings, merged_settings)
      |> assign(:setting_options, setting_options)
      |> assign(:registration_account_type_options, registration_account_type_options())
      |> assign(:changeset, changeset)
      |> assign(:saving, false)
      |> assign(
        :project_title,
        merged_settings["project_title"] || PhoenixKit.Config.get(:project_title, "PhoenixKit")
      )
      |> assign(:field_definitions, field_definitions)
      |> assign(:editing_field, nil)
      |> assign(:show_field_form, false)
      # Options management for select/radio/checkbox fields
      |> assign(:field_form_type, "text")
      |> assign(:field_form_options, [])
      |> assign(:new_option_value, "")

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  def handle_event("validate_settings", %{"settings" => settings_params}, socket) do
    changeset = Settings.validate_settings(settings_params)

    socket =
      socket
      # Params carry only what the form actually rendered, and this page has
      # fields behind conditionals (the account-type picker appears once
      # organization accounts are ticked). Assigning the bare params would drop
      # every key that was not on screen, so the field renders empty and its
      # dirty hint claims an unsaved change against a value nobody touched.
      # Submitted values still win; the merge only fills the gaps.
      |> assign(:settings, Map.merge(socket.assigns.saved_settings, settings_params))
      |> assign(:changeset, changeset)

    {:noreply, socket}
  end

  def handle_event("save_settings", %{"settings" => settings_params}, socket) do
    socket = assign(socket, :saving, true)

    case Settings.update_settings(settings_params) do
      {:ok, updated_settings} ->
        changeset = Settings.change_settings(updated_settings)

        socket =
          socket
          |> assign(:settings, updated_settings)
          |> assign(:saved_settings, updated_settings)
          |> assign(:changeset, changeset)
          |> assign(:saving, false)
          |> put_flash(:info, gettext("User settings updated successfully"))

        {:noreply, socket}

      {:error, errors} ->
        error_msg = format_error_message(errors)

        socket =
          socket
          |> assign(:saving, false)
          |> put_flash(:error, error_msg)

        {:noreply, socket}
    end
  end

  # Custom Fields Events

  def handle_event("show_add_field_form", _params, socket) do
    socket =
      socket
      |> assign(:show_field_form, true)
      |> assign(:editing_field, nil)
      |> assign(:field_form_type, "text")
      |> assign(:field_form_options, [])
      |> assign(:new_option_value, "")

    {:noreply, socket}
  end

  def handle_event("show_edit_field_form", %{"key" => key}, socket) do
    field = CustomFields.get_field_definition(key)

    socket =
      socket
      |> assign(:show_field_form, true)
      |> assign(:editing_field, field)
      |> assign(:field_form_type, (field && field["type"]) || "text")
      |> assign(:field_form_options, (field && field["options"]) || [])
      |> assign(:new_option_value, "")

    {:noreply, socket}
  end

  def handle_event("hide_field_form", _params, socket) do
    socket =
      socket
      |> assign(:show_field_form, false)
      |> assign(:editing_field, nil)
      |> assign(:field_form_type, "text")
      |> assign(:field_form_options, [])
      |> assign(:new_option_value, "")

    {:noreply, socket}
  end

  def handle_event("save_field", %{"field" => field_params}, socket) do
    # Include options from socket assigns for select/radio/checkbox types
    field_params =
      if socket.assigns.field_form_type in ~w(select radio checkbox) do
        Map.put(field_params, "options", socket.assigns.field_form_options)
      else
        field_params
      end

    result =
      if socket.assigns.editing_field do
        # Update existing field
        key = socket.assigns.editing_field["key"]
        CustomFields.update_field_definition(key, field_params)
      else
        # Add new field
        CustomFields.add_field_definition(field_params)
      end

    case result do
      {:ok, _setting} ->
        field_definitions = CustomFields.list_field_definitions()

        socket =
          socket
          |> assign(:field_definitions, field_definitions)
          |> assign(:show_field_form, false)
          |> assign(:editing_field, nil)
          |> assign(:field_form_type, "text")
          |> assign(:field_form_options, [])
          |> assign(:new_option_value, "")
          |> put_flash(:info, gettext("Custom field saved successfully"))

        {:noreply, socket}

      {:error, message} when is_binary(message) ->
        socket = put_flash(socket, :error, message)
        {:noreply, socket}

      {:error, changeset} ->
        # Handle Ecto changeset errors with detailed messages
        error_msg =
          case changeset do
            %Ecto.Changeset{} -> format_error_message(changeset)
            _ -> gettext("Failed to save custom field")
          end

        socket = put_flash(socket, :error, error_msg)
        {:noreply, socket}
    end
  end

  # Options management for select/radio/checkbox fields

  def handle_event("field_type_changed", %{"field" => %{"type" => type}}, socket) do
    {:noreply, assign(socket, :field_form_type, type)}
  end

  def handle_event("update_new_option", %{"key" => "Enter", "value" => value}, socket) do
    # Enter key pressed - add the option
    trimmed = String.trim(value || "")

    if trimmed != "" and trimmed not in socket.assigns.field_form_options do
      socket =
        socket
        |> assign(:field_form_options, socket.assigns.field_form_options ++ [trimmed])
        |> assign(:new_option_value, "")

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_event("update_new_option", %{"value" => value}, socket) do
    {:noreply, assign(socket, :new_option_value, value)}
  end

  def handle_event("add_field_option", _params, socket) do
    value = socket.assigns.new_option_value
    trimmed = String.trim(value || "")

    if trimmed != "" and trimmed not in socket.assigns.field_form_options do
      socket =
        socket
        |> assign(:field_form_options, socket.assigns.field_form_options ++ [trimmed])
        |> assign(:new_option_value, "")

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_event("remove_field_option", %{"index" => index_str}, socket) do
    index = String.to_integer(index_str)
    options = List.delete_at(socket.assigns.field_form_options, index)
    {:noreply, assign(socket, :field_form_options, options)}
  end

  def handle_event("delete_field", %{"key" => key}, socket) do
    case CustomFields.delete_field_definition(key) do
      {:ok, _setting} ->
        # Broadcast field deletion to other LiveViews (e.g., users table)
        CustomFieldsEvents.broadcast_field_deleted(key)

        field_definitions = CustomFields.list_field_definitions()

        socket =
          socket
          |> assign(:field_definitions, field_definitions)
          |> put_flash(:info, gettext("Custom field deleted successfully"))

        {:noreply, socket}

      {:error, _changeset} ->
        socket = put_flash(socket, :error, gettext("Failed to delete custom field"))
        {:noreply, socket}
    end
  end

  def handle_event("toggle_field_enabled", %{"key" => key}, socket) do
    field = CustomFields.get_field_definition(key)

    if field do
      new_enabled = !field["enabled"]

      case CustomFields.update_field_definition(key, %{"enabled" => new_enabled}) do
        {:ok, _setting} ->
          field_definitions = CustomFields.list_field_definitions()

          socket =
            socket
            |> assign(:field_definitions, field_definitions)
            |> put_flash(
              :info,
              if(new_enabled,
                do: gettext("Field '%{label}' enabled", label: field["label"]),
                else: gettext("Field '%{label}' disabled", label: field["label"])
              )
            )

          {:noreply, socket}

        {:error, _changeset} ->
          socket = put_flash(socket, :error, gettext("Failed to update field"))
          {:noreply, socket}
      end
    else
      {:noreply, put_flash(socket, :error, gettext("Field not found"))}
    end
  end

  # Helper functions

  defp format_error_message(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Map.values()
    |> List.flatten()
    |> Enum.join(", ")
  end

  def get_option_label(value, options) do
    Settings.get_option_label(value, options)
  end

  # Values come from the context (single source, shared with the changeset
  # allowlist); the labels are translated HERE. `gettext/1` needs a literal
  # msgid to extract, so each value gets its own clause — the same arrangement
  # as `PhoenixKitWeb.Components.Core.AdminLabel.preset_text/1`, and
  # `registration_account_type_test.exs` fails if a value ever loses one.
  defp registration_account_type_options do
    Enum.map(Settings.registration_account_type_options(), fn {_msgid, value} ->
      {registration_account_type_label(value), value}
    end)
  end

  @doc false
  def registration_account_type_label("choice"), do: gettext("Visitor chooses")
  def registration_account_type_label("person"), do: gettext("Personal accounts only")
  def registration_account_type_label("organization"), do: gettext("Organization accounts only")

  # Not reachable through the context list; kept so a value added there without
  # a clause degrades to a raw label instead of crashing the settings page.
  def registration_account_type_label(value), do: value
end
