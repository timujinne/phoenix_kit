defmodule PhoenixKit.KnownPackagesTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.KnownPackages

  @stub_name :"PhoenixKit.KnownPackagesTest.Stub"

  @hex_newsletters %{
    "name" => "phoenix_kit_newsletters",
    "latest_version" => "0.3.1",
    "meta" => %{
      "description" => "Email newsletters. hex_docs_icon_name: hero-newspaper"
    }
  }

  @hex_posts %{
    "name" => "phoenix_kit_posts",
    "latest_version" => "0.2.0",
    "meta" => %{"description" => "Blog posts and tags. hex_docs_icon_name: hero-pencil-square"}
  }

  @hex_phoenix_kit %{
    "name" => "phoenix_kit",
    "latest_version" => "1.7.0",
    "meta" => %{"description" => "The core library."}
  }

  setup do
    KnownPackages.clear_cache()
    original_extras = Application.get_env(:phoenix_kit, :extra_known_packages, [])

    on_exit(fn ->
      KnownPackages.clear_cache()
      Application.put_env(:phoenix_kit, :extra_known_packages, original_extras)
    end)

    :ok
  end

  # Pass test stub via opts arg (no Application.put_env).
  defp test_opts(extra \\ []) do
    Keyword.merge(
      [req_options: [plug: {Req.Test, @stub_name}, retry: false]],
      extra
    )
  end

  defp stub_hex(packages) do
    Req.Test.stub(@stub_name, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(packages))
    end)
  end

  describe "list/1 happy path" do
    test "returns shaped entries from Hex" do
      stub_hex([@hex_newsletters, @hex_posts])

      packages = KnownPackages.list(test_opts())

      assert length(packages) == 2

      newsletters = Enum.find(packages, &(&1.package == "phoenix_kit_newsletters"))
      assert newsletters.key == "newsletters"
      assert newsletters.name == "Newsletters"
      assert newsletters.description == "Email newsletters."
      assert newsletters.icon == "hero-newspaper"
      assert newsletters.hex_url == "https://hex.pm/packages/phoenix_kit_newsletters"
      assert newsletters.source == "hex"
    end

    test "filters out phoenix_kit core package" do
      stub_hex([@hex_phoenix_kit, @hex_newsletters])

      packages = KnownPackages.list(test_opts())

      package_names = Enum.map(packages, & &1.package)
      refute "phoenix_kit" in package_names
      assert "phoenix_kit_newsletters" in package_names
    end

    test "entry without icon marker gets default icon" do
      pkg = %{
        "name" => "phoenix_kit_crm",
        "latest_version" => "0.1.0",
        "meta" => %{"description" => "CRM module without marker"}
      }

      stub_hex([pkg])

      packages = KnownPackages.list(test_opts())

      crm = Enum.find(packages, &(&1.package == "phoenix_kit_crm"))
      assert crm.icon == "hero-puzzle-piece"
      assert crm.description == "CRM module without marker"
    end

    test "humanizes multi-word package key" do
      pkg = %{
        "name" => "phoenix_kit_customer_support",
        "latest_version" => "0.1.0",
        "meta" => %{"description" => "Customer support tools."}
      }

      stub_hex([pkg])

      packages = KnownPackages.list(test_opts())

      support = Enum.find(packages, &(&1.package == "phoenix_kit_customer_support"))
      assert support.name == "Customer Support"
    end
  end

  describe "entry shape (backward-compat fields)" do
    setup do
      stub_hex([@hex_newsletters])
      :ok
    end

    test "module field uses heuristic" do
      [pkg] = KnownPackages.list(test_opts())
      assert pkg.module == :"Elixir.PhoenixKitNewsletters"
    end

    test "hex_package equals package" do
      [pkg] = KnownPackages.list(test_opts())
      assert pkg.hex_package == pkg.package
    end

    test "github_url falls back to BeamLabEU/{package} when Hex meta has no link" do
      [pkg] = KnownPackages.list(test_opts())
      assert pkg.github_url == "https://github.com/BeamLabEU/phoenix_kit_newsletters"
    end

    test "github_url respects Hex meta.links.GitHub when present" do
      pkg_with_link = %{
        "name" => "phoenix_kit_with_link",
        "latest_version" => "0.1.0",
        "meta" => %{
          "description" => "Has explicit GitHub link.",
          "links" => %{"GitHub" => "https://github.com/elsewhere/repo"}
        }
      }

      stub_hex([pkg_with_link])
      KnownPackages.clear_cache()

      [pkg] = KnownPackages.list(test_opts())
      assert pkg.github_url == "https://github.com/elsewhere/repo"
    end

    test "latest_version pulled from Hex meta" do
      [pkg] = KnownPackages.list(test_opts())
      assert pkg.latest_version == "0.3.1"
    end

    test "all 11 keys present" do
      [pkg] = KnownPackages.list(test_opts())

      assert Enum.sort(Map.keys(pkg)) == [
               :description,
               :github_url,
               :hex_package,
               :hex_url,
               :icon,
               :key,
               :latest_version,
               :module,
               :name,
               :package,
               :source
             ]
    end
  end

  describe "caching" do
    test "second call does not re-hit Hex (cache hit)" do
      call_count = :counters.new(1, [])

      Req.Test.stub(@stub_name, fn conn ->
        :counters.add(call_count, 1, 1)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!([@hex_newsletters]))
      end)

      KnownPackages.list(test_opts())
      KnownPackages.list(test_opts())

      assert :counters.get(call_count, 1) == 1
    end

    test "after clear_cache/0 a new fetch happens" do
      call_count = :counters.new(1, [])

      Req.Test.stub(@stub_name, fn conn ->
        :counters.add(call_count, 1, 1)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!([@hex_newsletters]))
      end)

      KnownPackages.list(test_opts())
      KnownPackages.clear_cache()
      KnownPackages.list(test_opts())

      assert :counters.get(call_count, 1) == 2
    end
  end

  describe "Hex failure handling" do
    test "Hex 500 returns no Hex-sourced entries with Logger.warning" do
      Req.Test.stub(@stub_name, fn conn ->
        Plug.Conn.send_resp(conn, 500, "Internal Server Error")
      end)

      log =
        capture_log(fn ->
          result = KnownPackages.list(test_opts())
          refute Enum.any?(result, &(&1.source == "hex"))
        end)

      assert log =~ "Hex fetch failed"
    end

    test "Hex transport error returns list with Logger.warning" do
      Req.Test.stub(@stub_name, fn _conn ->
        raise "connection refused"
      end)

      log =
        capture_log(fn ->
          result = KnownPackages.list(test_opts())
          assert is_list(result)
        end)

      assert log =~ "Hex fetch failed"
    end

    test "an unreachable Hex is reported as :unavailable, not as an empty catalog" do
      # These look identical to an operator: the admin Modules page hid the
      # whole "Available Packages" section on an empty list, so a network
      # failure read as "there are no packages to install". Only one of those
      # two situations is true at a time and the UI has to be able to tell.
      Req.Test.stub(@stub_name, fn _conn -> raise "connection refused" end)

      capture_log(fn -> KnownPackages.list(test_opts()) end)

      assert KnownPackages.status() == :unavailable
    end

    test "a successful fetch reports :ok" do
      stub_hex([@hex_newsletters])

      KnownPackages.list(test_opts())

      assert KnownPackages.status() == :ok
    end

    test "browse_url/0 points at the human version of the search the code runs" do
      # The fallback offered when hex is unreachable. A link stays current
      # because Hex maintains it; a catalog bundled into core would need a core
      # release to add a package.
      url = KnownPackages.browse_url()

      assert url =~ "hex.pm"
      assert url =~ "phoenix_kit_"
    end

    test "Hex 200 with non-list body returns no Hex-sourced entries" do
      Req.Test.stub(@stub_name, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"unexpected" => "shape"}))
      end)

      log =
        capture_log(fn ->
          result = KnownPackages.list(test_opts())
          refute Enum.any?(result, &(&1.source == "hex"))
        end)

      assert log =~ "Hex fetch failed"
    end
  end

  describe "stale cache (stale-while-revalidate with cap)" do
    test "stale data is served on Hex failure when within max stale age" do
      # First successful fetch populates cache.
      stub_hex([@hex_newsletters])
      assert [_pkg] = KnownPackages.list(test_opts(ttl_ms: 0))

      # Now Hex starts failing.
      Req.Test.stub(@stub_name, fn conn ->
        Plug.Conn.send_resp(conn, 500, "Internal Server Error")
      end)

      log =
        capture_log(fn ->
          # ttl=0 forces refetch on every call; max_stale_age large so stale wins.
          result =
            KnownPackages.list(test_opts(ttl_ms: 0, max_stale_age_ms: :timer.hours(1)))

          newsletters = Enum.find(result, &(&1.package == "phoenix_kit_newsletters"))
          assert newsletters != nil
          assert newsletters.source == "hex"
        end)

      assert log =~ "serving stale data"
    end

    test "stale data is dropped beyond max stale age" do
      stub_hex([@hex_newsletters])
      assert [_pkg] = KnownPackages.list(test_opts(ttl_ms: 0))

      Req.Test.stub(@stub_name, fn conn ->
        Plug.Conn.send_resp(conn, 500, "Internal Server Error")
      end)

      :timer.sleep(20)

      log =
        capture_log(fn ->
          result = KnownPackages.list(test_opts(ttl_ms: 0, max_stale_age_ms: 10))

          refute Enum.any?(result, &(&1.source == "hex"))
        end)

      assert log =~ "exceeds max stale age"
    end
  end

  describe "pagination" do
    test "fetches multiple pages via Link header" do
      page2_pkg = %{
        "name" => "phoenix_kit_crm",
        "latest_version" => "0.1.0",
        "meta" => %{"description" => "CRM module."}
      }

      page2_url = "https://hex.pm/api/packages?search=phoenix_kit_&sort=name&page=2"

      Req.Test.stub(@stub_name, fn conn ->
        {packages, add_link} =
          if String.contains?(conn.request_path <> "?" <> (conn.query_string || ""), "page=2") do
            {[page2_pkg], false}
          else
            {[@hex_newsletters], true}
          end

        conn =
          if add_link do
            Plug.Conn.put_resp_header(conn, "link", "<#{page2_url}>; rel=\"next\"")
          else
            conn
          end

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(packages))
      end)

      packages = KnownPackages.list(test_opts())

      package_names = Enum.map(packages, & &1.package)
      assert "phoenix_kit_newsletters" in package_names
      assert "phoenix_kit_crm" in package_names
    end
  end

  describe "extra_known_packages config" do
    test "valid config entries appear in result" do
      Application.put_env(:phoenix_kit, :extra_known_packages, [
        %{
          key: "private_billing",
          package: "my_app_billing",
          name: "Private Billing",
          description: "Internal billing module",
          icon: "hero-credit-card",
          hex_url: "https://hex.pm/packages/my_app_billing"
        }
      ])

      stub_hex([])

      packages = KnownPackages.list(test_opts())

      billing = Enum.find(packages, &(&1.package == "my_app_billing"))
      assert billing != nil
      assert billing.source == "config"
      assert billing.name == "Private Billing"
      # Back-compat fields filled with sane defaults for config entries.
      assert billing.hex_package == "my_app_billing"
      assert billing.module == nil
      assert billing.github_url == nil
      assert billing.latest_version == nil
    end

    test "config entry wins over Hex entry with same package" do
      Application.put_env(:phoenix_kit, :extra_known_packages, [
        %{
          key: "newsletters",
          package: "phoenix_kit_newsletters",
          name: "Newsletters (custom)",
          description: "Overridden via config",
          icon: "hero-star",
          hex_url: "https://hex.pm/packages/phoenix_kit_newsletters"
        }
      ])

      stub_hex([@hex_newsletters])

      packages = KnownPackages.list(test_opts())

      newsletters_entries = Enum.filter(packages, &(&1.package == "phoenix_kit_newsletters"))
      assert length(newsletters_entries) == 1
      assert hd(newsletters_entries).name == "Newsletters (custom)"
      assert hd(newsletters_entries).source == "config"
    end
  end
end
