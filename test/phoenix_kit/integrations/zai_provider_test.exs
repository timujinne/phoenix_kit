defmodule PhoenixKit.Integrations.ZaiProviderTest do
  @moduledoc """
  The built-in `zai` provider: what the registry declares, and the key check
  against `GET /api/paas/v4/models` with `Authorization: Bearer <key>` — the
  plain generic check, no `extra_headers`.

  The key check is routed through `Req.Test` (`:integrations_check_req_options`);
  nothing here opens a socket.
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Integrations.Providers

  @stub __MODULE__.Stub

  # Headers `Req` adds on its own; everything else on the wire is ours.
  @req_default_headers ~w(accept-encoding user-agent host content-length)

  setup do
    previous = Application.fetch_env(:phoenix_kit, :integrations_check_req_options)

    Application.put_env(:phoenix_kit, :integrations_check_req_options,
      plug: {Req.Test, @stub},
      retry: false
    )

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:phoenix_kit, :integrations_check_req_options, value)
        :error -> Application.delete_env(:phoenix_kit, :integrations_check_req_options)
      end
    end)

    :ok
  end

  describe "registry" do
    test "is a built-in API-key provider usable site-wide and personally" do
      p = Providers.get("zai")

      assert p.name == "Z.ai"
      assert p.icon == "hero-sparkles"
      assert p.auth_type == :api_key
      assert p.oauth_config == nil
      assert p.capabilities == [:ai_completions]
      assert Providers.scopes_of(p) == [:system, :personal]

      assert p in Providers.for_scope(:system)
      assert p in Providers.for_scope(:personal)
      assert p in Providers.with_capability(:ai_completions)
    end

    test "is not pre-offered to users: an admin opts it in" do
      refute Map.get(Providers.get("zai"), :personal_default)
    end

    test "the description names the GLM models" do
      assert Providers.get("zai").description =~ "GLM"
    end

    test "base_url is the general OpenAI-compatible API, without a trailing slash" do
      # AI consumers build `base_url <> "/chat/completions"`.
      assert Providers.base_url("zai") == "https://api.z.ai/api/paas/v4"
      assert Providers.base_url("zai:work") == "https://api.z.ai/api/paas/v4"
    end

    test "asks for one required, masked api_key" do
      assert [field] = Providers.get("zai").setup_fields

      assert %{key: "api_key", type: :password, required: true} = field
      assert field.placeholder == "xxxxxxxx.xxxxxxxx"
      assert field.help =~ "z.ai/manage-apikey/apikey-list"
      assert "api_key" in Encryption.sensitive_fields()
    end

    test "instructions lead from the account to a pasted key, the same on both surfaces" do
      p = Providers.get("zai")
      sections = Providers.instructions_for(p, :system)
      text = sections |> Enum.flat_map(& &1.steps) |> Enum.map_join("\n", &elem(&1, 0))

      assert text =~ "https://z.ai/model-api"
      assert text =~ "https://z.ai/manage-apikey/billing"
      assert text =~ "1113"
      assert text =~ "https://z.ai/manage-apikey/apikey-list"
      assert text =~ "Standard API Key"
      assert text =~ "paste it into the form above"
      refute text =~ "coding/paas"

      assert Enum.any?(sections, &(Map.get(&1, :note, "") =~ "Coding Plan"))

      assert Providers.instructions_for(p, :personal) == sections
    end

    test "declares the plain Bearer key check against /models" do
      assert Providers.get("zai").validation == %{
               url: "https://api.z.ai/api/paas/v4/models",
               method: :get,
               auth_header: "Authorization",
               auth_prefix: "Bearer "
             }
    end
  end

  describe "key check" do
    test "GETs /api/paas/v4/models with the key as a Bearer token, and nothing more" do
      test_pid = self()

      Req.Test.stub(@stub, fn conn ->
        send(test_pid, {:request, conn.method, conn.host, conn.request_path, conn.req_headers})
        Req.Test.json(conn, %{"object" => "list", "data" => []})
      end)

      assert :ok = check("0123abcd.efgh4567")

      assert_received {:request, "GET", "api.z.ai", "/api/paas/v4/models", headers}

      assert [{"authorization", "Bearer 0123abcd.efgh4567"}] ==
               Enum.reject(headers, fn {name, _} -> name in @req_default_headers end)
    end

    test "a rejected key is reported as invalid credentials" do
      Req.Test.stub(@stub, fn conn ->
        conn
        |> Plug.Conn.put_status(401)
        |> Req.Test.json(%{"error" => %{"code" => "1000", "message" => "Authentication Failed"}})
      end)

      assert {:error, "Invalid credentials"} = check("bad.key")
    end

    test "other answers keep the generic wording" do
      for {status, expected} <- [{403, "Access denied"}, {429, "Service error 429"}] do
        Req.Test.stub(@stub, fn conn -> Plug.Conn.send_resp(conn, status, "") end)

        assert {:error, ^expected} = check("0123abcd.efgh4567")
      end
    end

    test "an unreachable API is reported as such" do
      Req.Test.stub(@stub, &Req.Test.transport_error(&1, :econnrefused))

      assert {:error, "Could not reach the service"} = check("0123abcd.efgh4567")
    end

    test "a blank key never leaves the machine" do
      Req.Test.stub(@stub, fn _conn -> flunk("a blank key must not be sent") end)

      assert {:error, "No credentials configured"} = check("")
    end
  end

  defp check(key),
    do: Integrations.__do_validate__(Providers.get("zai"), %{"api_key" => key})
end
