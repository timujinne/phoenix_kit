defmodule PhoenixKit.Modules.Crawlers.RobotsTxtTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Crawlers.Bots
  alias PhoenixKit.Modules.Crawlers.RobotsTxt

  describe "build_for/2" do
    test "nothing blocked: allow-all stanza plus sitemap line, no Disallow: /" do
      out = RobotsTxt.build_for([], sitemap_url: "https://example.com/sitemap.xml")

      assert out =~ "User-agent: *"
      assert out =~ ~r/^Disallow:$/m
      refute out =~ "Disallow: /"
      assert out =~ "Sitemap: https://example.com/sitemap.xml"
    end

    test "a blocked group lists every one of its tokens over one Disallow: /" do
      out = RobotsTxt.build_for([:ai_training], [])

      group = Bots.group(:ai_training)

      for bot <- group.bots do
        assert out =~ "User-agent: #{bot.token}"
      end

      assert out =~ "Disallow: /"
      # robots.txt-only tokens ARE addressed here — robots.txt is exactly
      # where Google-Extended is spoken to, unlike the UA blocker.
      assert out =~ "User-agent: Google-Extended"
    end

    test "unblocked groups do not appear" do
      out = RobotsTxt.build_for([:ai_training], [])

      refute out =~ "User-agent: Googlebot"
      refute out =~ "User-agent: AhrefsBot"
    end

    test "no sitemap url, no Sitemap line" do
      refute RobotsTxt.build_for([], []) =~ "Sitemap:"
    end

    test "unknown group keys are skipped, not raised on" do
      out = RobotsTxt.build_for([:no_such_group], [])
      assert out =~ "User-agent: *"
    end

    test "ends with a trailing newline" do
      assert String.ends_with?(RobotsTxt.build_for([], []), "\n")
    end
  end

  describe "the registry it renders from" do
    test "every group has at least one bot and unique tokens overall" do
      all_tokens = Enum.flat_map(Bots.groups(), fn g -> Enum.map(g.bots, & &1.token) end)

      assert Enum.all?(Bots.groups(), &(&1.bots != []))
      assert length(all_tokens) == length(Enum.uniq(all_tokens))
    end

    test "ua_fragments excludes robots.txt-only tokens and is lowercase" do
      fragments = Bots.ua_fragments([:ai_training])

      refute Enum.any?(fragments, &(&1 =~ ~r/google-extended|applebot-extended/))
      assert Enum.all?(fragments, &(&1 == String.downcase(&1)))
      assert "gptbot" in fragments
    end

    test "group/1 resolves strings and atoms to the same group" do
      assert Bots.group(:search) == Bots.group("search")
      assert Bots.group("nope") == nil
    end
  end
end
