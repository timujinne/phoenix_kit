defmodule PhoenixKit.API.FlowConfig do
  @moduledoc """
  Settings of the dangerous-operation flow of the machine API: when an operation needs
  a confirmation, how long a code, an approval and a stored idempotent answer live.

  | Setting | Default | Allowed |
  |---|---|---|
  | `api_confirm_batch_over` | `50` | 1 to 500 |
  | `api_confirm_ttl_seconds` | `120` | 10 to 600 |
  | `api_user_confirm_ttl_seconds` | `600` | 60 to 86400 |
  | `api_approval_ttl_hours` | `72` | 1 to 720 |
  | `api_approval_pending_max` | `20` | 1 to 1000 |
  | `api_idempotency_ttl_hours` | `24` | 1 to 720 |
  | `api_idempotency_lease_seconds` | `120` | 5 to 3600 |

  (A module that tunes a flow threshold, such as `api_confirm_price_change_pct`, owns that setting.)

  A stored value that does not parse or is below its minimum reads as the default;
  one above its maximum reads as the maximum. A Settings read error reads as the
  default (`PhoenixKit.API.Config.int/2`).

  The same table drives the form on Settings -> API: `fields/0`, `current/0`,
  `validate/1` and `save/2`. The form is all or nothing: one invalid field saves
  nothing, and only the values that changed are written (each as a permanent
  `setting.changed` Activity entry through `Settings.update_setting_with_module/4`).
  """

  alias PhoenixKit.API.Config
  alias PhoenixKit.Settings

  @fields [
    %{
      field: "confirm_batch_over",
      setting: "api_confirm_batch_over",
      default: 50,
      min: 1,
      max: 500,
      reader: :confirm_batch_over
    },
    %{
      field: "confirm_ttl_seconds",
      setting: "api_confirm_ttl_seconds",
      default: 120,
      min: 10,
      max: 600,
      reader: :confirm_ttl_seconds
    },
    %{
      field: "user_confirm_ttl_seconds",
      setting: "api_user_confirm_ttl_seconds",
      default: 600,
      min: 60,
      max: 86_400,
      reader: :user_confirm_ttl_seconds
    },
    %{
      field: "approval_ttl_hours",
      setting: "api_approval_ttl_hours",
      default: 72,
      min: 1,
      max: 720,
      reader: :approval_ttl_hours
    },
    %{
      field: "approval_pending_max",
      setting: "api_approval_pending_max",
      default: 20,
      min: 1,
      max: 1000,
      reader: :approval_pending_max
    },
    %{
      field: "idempotency_ttl_hours",
      setting: "api_idempotency_ttl_hours",
      default: 24,
      min: 1,
      max: 720,
      reader: :idempotency_ttl_hours
    },
    %{
      field: "idempotency_lease_seconds",
      setting: "api_idempotency_lease_seconds",
      default: 120,
      min: 5,
      max: 3600,
      reader: :idempotency_lease_seconds
    }
  ]

  @doc "Rows above which an admin write is dangerous (`api_confirm_batch_over`)."
  @spec confirm_batch_over() :: pos_integer()
  def confirm_batch_over, do: read("api_confirm_batch_over")

  @doc "Seconds a confirmation code lives (`api_confirm_ttl_seconds`, at most 600)."
  @spec confirm_ttl_seconds() :: pos_integer()
  def confirm_ttl_seconds, do: read("api_confirm_ttl_seconds")

  @doc """
  Seconds a confirmation of a person's live session lives (`api_user_confirm_ttl_seconds`,
  at most a day): the person confirms in the page, which takes longer than an agent's
  second call.
  """
  @spec user_confirm_ttl_seconds() :: pos_integer()
  def user_confirm_ttl_seconds, do: read("api_user_confirm_ttl_seconds")

  @doc "Hours a pending approval lives (`api_approval_ttl_hours`)."
  @spec approval_ttl_hours() :: pos_integer()
  def approval_ttl_hours, do: read("api_approval_ttl_hours")

  @doc "Hours a stored idempotent answer lives (`api_idempotency_ttl_hours`)."
  @spec idempotency_ttl_hours() :: pos_integer()
  def idempotency_ttl_hours, do: read("api_idempotency_ttl_hours")

  @doc "Seconds an `in_progress` idempotency claim holds before a retry may take over."
  @spec idempotency_lease_seconds() :: pos_integer()
  def idempotency_lease_seconds, do: read("api_idempotency_lease_seconds")

  @doc "Pending approvals one key may hold (`api_approval_pending_max`)."
  @spec approval_pending_max() :: pos_integer()
  def approval_pending_max, do: read("api_approval_pending_max")

  @doc "The seven fields of the form, in the order the page shows them."
  @spec fields() :: [map()]
  def fields, do: @fields

  @doc "The current value of every form field, as the text the field shows."
  @spec current() :: %{String.t() => String.t()}
  def current do
    Map.new(@fields, fn %{field: field, reader: reader} ->
      {field, __MODULE__ |> apply(reader, []) |> Integer.to_string()}
    end)
  end

  @doc """
  Checks a submitted form. `{:ok, [{setting, integer}]}` when every field is a whole
  number inside its range; otherwise `{:error, fields}` naming every bad field
  (a missing field is bad, never the default).
  """
  @spec validate(map()) :: {:ok, [{String.t(), integer()}]} | {:error, [String.t()]}
  def validate(params) when is_map(params) do
    parsed =
      Enum.map(@fields, fn %{field: field, setting: setting, min: min, max: max} ->
        {field, setting, parse(Map.get(params, field), min, max)}
      end)

    case for({field, _setting, :error} <- parsed, do: field) do
      [] -> {:ok, for({_field, setting, {:ok, number}} <- parsed, do: {setting, number})}
      bad -> {:error, bad}
    end
  end

  def validate(_params), do: {:error, Enum.map(@fields, & &1.field)}

  @doc """
  Validates and writes a form. Returns the settings that changed. `opts` are the
  history options of `Settings.update_setting_with_module/4` (`actor_uuid:`,
  `source:`).
  """
  @spec save(map(), keyword()) :: {:ok, [String.t()]} | {:error, [String.t()] | :save_failed}
  def save(params, opts) do
    with {:ok, pairs} <- validate(params) do
      current = current()
      fields = Map.new(@fields, &{&1.setting, &1.field})

      changed =
        for {setting, number} <- pairs,
            Integer.to_string(number) != current[fields[setting]],
            do: {setting, number}

      results =
        Enum.map(changed, fn {setting, number} ->
          Settings.update_setting_with_module(setting, Integer.to_string(number), "api", opts)
        end)

      if Enum.all?(results, &match?({:ok, _setting}, &1)),
        do: {:ok, Enum.map(changed, &elem(&1, 0))},
        else: {:error, :save_failed}
    end
  end

  # --- reading ---------------------------------------------------------

  defp read(setting) do
    %{default: default, min: min, max: max} = Enum.find(@fields, &(&1.setting == setting))

    case Config.int(setting, default) do
      value when value > max -> max
      value when value >= min -> value
      _below_minimum -> default
    end
  end

  defp parse(value, min, max) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {number, ""} when number >= min and number <= max -> {:ok, number}
      _ -> :error
    end
  end

  defp parse(_value, _min, _max), do: :error
end
