defmodule PhoenixKit.Integrations.AnthropicProviderTest do
  @moduledoc """
  The built-in `anthropic` provider: what the registry declares, and the key
  check against `GET /v1/models` with Anthropic's native `x-api-key` and
  `anthropic-version` headers (`validation.extra_headers`).

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
      p = Providers.get("anthropic")

      assert p.name == "Anthropic"
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
      refute Map.get(Providers.get("anthropic"), :personal_default)
    end

    test "the description names the Claude model families" do
      description = Providers.get("anthropic").description

      for family <- ~w(Opus Sonnet Haiku), do: assert(description =~ family)
    end

    test "base_url is the OpenAI-compatible layer, without a trailing slash" do
      # AI consumers build `base_url <> "/chat/completions"`.
      assert Providers.base_url("anthropic") == "https://api.anthropic.com/v1"
      assert Providers.base_url("anthropic:work") == "https://api.anthropic.com/v1"
    end

    test "asks for one required, masked api_key" do
      assert [field] = Providers.get("anthropic").setup_fields

      assert %{key: "api_key", type: :password, required: true, placeholder: "sk-ant-..."} = field
      assert field.help =~ "platform.claude.com/settings/keys"
      assert "api_key" in Encryption.sensitive_fields()
    end

    test "instructions lead from the account to a pasted key, the same on both surfaces" do
      p = Providers.get("anthropic")
      sections = Providers.instructions_for(p, :system)
      text = sections |> Enum.flat_map(& &1.steps) |> Enum.map_join("\n", &elem(&1, 0))

      assert text =~ "https://platform.claude.com"
      refute text =~ "console.anthropic.com"
      assert text =~ "Billing"
      assert text =~ "API Keys"
      assert text =~ "Create Key"
      assert text =~ "single workspace"
      assert text =~ "paste it into the form above"

      assert Providers.instructions_for(p, :personal) == sections
    end

    test "declares Anthropic's native key check, not the Bearer one" do
      assert Providers.get("anthropic").validation == %{
               url: "https://api.anthropic.com/v1/models",
               method: :get,
               auth_header: "x-api-key",
               auth_prefix: "",
               extra_headers: [{"anthropic-version", "2023-06-01"}]
             }
    end
  end

  describe "key check" do
    test "GETs /v1/models with x-api-key and anthropic-version, and no Bearer" do
      test_pid = self()

      Req.Test.stub(@stub, fn conn ->
        send(test_pid, {:request, conn.method, conn.host, conn.request_path, conn.req_headers})
        Req.Test.json(conn, %{"data" => [], "has_more" => false})
      end)

      assert :ok = check("sk-ant-api03-test")

      assert_received {:request, "GET", "api.anthropic.com", "/v1/models", headers}
      assert {"x-api-key", "sk-ant-api03-test"} in headers
      assert {"anthropic-version", "2023-06-01"} in headers
      refute List.keymember?(headers, "authorization", 0)
    end

    test "a rejected key is reported as invalid credentials" do
      Req.Test.stub(@stub, fn conn ->
        conn
        |> Plug.Conn.put_status(401)
        |> Req.Test.json(%{
          "type" => "error",
          "error" => %{"type" => "authentication_error", "message" => "invalid x-api-key"}
        })
      end)

      assert {:error, "Invalid credentials"} = check("sk-ant-bad")
    end

    test "other answers keep the generic wording" do
      for {status, expected} <- [
            {403, "Access denied"},
            {429, "Service error 429"},
            {529, "Service error 529"}
          ] do
        Req.Test.stub(@stub, fn conn -> Plug.Conn.send_resp(conn, status, "") end)

        assert {:error, ^expected} = check("sk-ant-test")
      end
    end

    test "an unreachable API is reported as such" do
      Req.Test.stub(@stub, &Req.Test.transport_error(&1, :econnrefused))

      assert {:error, "Could not reach the service"} = check("sk-ant-test")
    end

    test "a blank key never leaves the machine" do
      Req.Test.stub(@stub, fn _conn -> flunk("a blank key must not be sent") end)

      assert {:error, "No credentials configured"} = check("")
    end
  end

  describe "validation.extra_headers" do
    test "are sent along with the auth header, as declared" do
      provider = synthetic(extra_headers: [{"x-one", "1"}, {"x-two", "2"}])

      # Presence only: `Req` keeps request headers in a map, so their order on
      # the wire is not observable here.
      assert [{"x-key", "K secret"}, {"x-one", "1"}, {"x-two", "2"}] ==
               Enum.sort(request_headers(fn -> validate(provider, "secret") end))
    end

    test "a provider that declares none sends only its own auth header" do
      assert [{"x-key", "K secret"}] ==
               request_headers(fn -> validate(synthetic([]), "secret") end)
    end

    test "an explicit nil sends only the auth header too" do
      assert [{"x-key", "K secret"}] ==
               request_headers(fn -> validate(synthetic(extra_headers: nil), "secret") end)
    end

    test "no other built-in key check changed: each sends its auth header and nothing more" do
      checked =
        for p <- Providers.all(),
            p.key != "anthropic",
            p.auth_type in [:api_key, :bot_token],
            match?(%{url: _}, p[:validation]),
            do: p

      # The generic check is what OpenAI, OpenRouter, Mistral, DeepSeek, xAI,
      # ElevenLabs and GitHub use.
      assert length(checked) >= 7

      for p <- checked do
        v = p.validation
        refute Map.has_key?(v, :extra_headers), "#{p.key} declares extra_headers"

        assert [{String.downcase(v.auth_header), v.auth_prefix <> "secret"}] ==
                 request_headers(fn -> validate(p, "secret") end),
               "#{p.key} request headers changed"
      end
    end

    test "the Req.Test seam passes the plug and retry, nothing else" do
      Application.put_env(:phoenix_kit, :integrations_check_req_options,
        plug: {Req.Test, @stub},
        headers: [{"x-evil", "1"}]
      )

      assert [{"x-key", "K secret"}] ==
               request_headers(fn -> validate(synthetic([]), "secret") end)
    end
  end

  defp check(key), do: validate(Providers.get("anthropic"), key)

  defp validate(provider, key),
    do: Integrations.__do_validate__(provider, %{"api_key" => key})

  defp synthetic(extra) do
    validation =
      Map.merge(
        %{
          url: "https://check.example/ping",
          method: :get,
          auth_header: "x-key",
          auth_prefix: "K "
        },
        Map.new(extra)
      )

    %{key: "synthetic", auth_type: :api_key, validation: validation}
  end

  # The headers one stubbed request carried, minus what `Req` adds itself.
  defp request_headers(fun) do
    test_pid = self()

    Req.Test.stub(@stub, fn conn ->
      send(test_pid, {:headers, conn.req_headers})
      Req.Test.json(conn, %{})
    end)

    assert :ok = fun.()
    assert_received {:headers, headers}

    Enum.reject(headers, fn {name, _value} -> name in @req_default_headers end)
  end
end
