defmodule PhoenixKit.Integration.Integrations.PersonalSmtpPolicyTest do
  @moduledoc """
  With `config :phoenix_kit, :personal_smtp_policy, :restricted`, "Test
  Connection" on a personal SMTP connection — saved or still in the form — is
  refused before a socket opens when the host is internal or the port is not a
  mail port. Website-wide connections are checked exactly as before.
  """

  # async: false — the policy is read from the application environment.
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integrations

  setup do
    Application.put_env(:phoenix_kit, :personal_smtp_policy, :restricted)
    on_exit(fn -> Application.delete_env(:phoenix_kit, :personal_smtp_policy) end)
    %{owner: {:user, Ecto.UUID.generate()}}
  end

  # Accepts one connection, reports it, and hangs up.
  defp hang_up_relay do
    test = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    server =
      spawn(fn ->
        case :gen_tcp.accept(listener) do
          {:ok, socket} ->
            send(test, :relay_accepted)
            :gen_tcp.close(socket)
            # A retry must find nothing listening, not a backlog that never
            # answers.
            :gen_tcp.close(listener)

          _ ->
            :ok
        end
      end)

    on_exit(fn ->
      Process.exit(server, :kill)
      :gen_tcp.close(listener)
    end)

    port
  end

  defp attrs(host, port),
    do: %{"host" => host, "port" => to_string(port), "username" => "u", "password" => "p"}

  describe "validate_connection/3" do
    test "a saved personal connection to an internal address is refused", %{owner: owner} do
      {:ok, %{uuid: uuid}} = Integrations.add_connection("smtp", "mine", nil, owner: owner)
      {:ok, _} = Integrations.save_setup(uuid, attrs("127.0.0.1", 587), nil, owner: owner)

      assert {:error, message} = Integrations.validate_connection(uuid, nil, owner: owner)
      assert message =~ "public address"
    end

    test "a saved system connection still reaches the relay" do
      port = hang_up_relay()
      {:ok, %{uuid: uuid}} = Integrations.add_connection("smtp", "site relay")
      {:ok, _} = Integrations.save_setup(uuid, attrs("127.0.0.1", port))

      assert {:error, message} = Integrations.validate_connection(uuid, nil, owner: :system)
      refute message =~ "public address"
      assert_receive :relay_accepted, 5_000
    end
  end

  describe "reading/2 (a check run without the caller's owner on the validator)" do
    test "a system connection still reaches the relay" do
      port = hang_up_relay()
      {:ok, %{uuid: uuid}} = Integrations.add_connection("smtp", "site relay")
      {:ok, _} = Integrations.save_setup(uuid, attrs("127.0.0.1", port))

      assert {:error, message} = Integrations.reading(uuid)
      refute message =~ "public address"
      refute message =~ "25, 465, 587"
      assert_receive :relay_accepted, 5_000
    end

    test "a personal connection is refused without connecting", %{owner: owner} do
      port = hang_up_relay()
      {:ok, %{uuid: uuid}} = Integrations.add_connection("smtp", "mine", nil, owner: owner)
      {:ok, _} = Integrations.save_setup(uuid, attrs("127.0.0.1", port), nil, owner: owner)

      assert {:error, message} = Integrations.reading(uuid, owner: owner)
      assert message =~ "25, 465, 587"
      refute_receive :relay_accepted, 200
    end
  end

  describe "validate_credentials/3 (the form's test-before-save)" do
    test "a personal probe on a non-mail port is refused without connecting", %{owner: owner} do
      port = hang_up_relay()

      assert {:error, message} =
               Integrations.validate_credentials("smtp", attrs("127.0.0.1", port), owner: owner)

      assert message =~ "25, 465, 587"
      refute_receive :relay_accepted, 200
    end

    test "a website-wide probe is not affected" do
      port = hang_up_relay()

      assert {:error, _} =
               Integrations.validate_credentials("smtp", attrs("127.0.0.1", port), owner: :system)

      assert_receive :relay_accepted, 5_000
    end
  end
end
