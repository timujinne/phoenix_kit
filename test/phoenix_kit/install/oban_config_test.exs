defmodule PhoenixKit.Install.ObanConfigTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Install.ObanConfig
  alias PhoenixKit.Notifications.ChannelConfig

  describe "oban_block_missing_prefix?/1" do
    test "true when the Oban block lacks prefix:" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]

      config :my_app, MyAppWeb.Endpoint, url: [host: "localhost"]
      """

      assert ObanConfig.oban_block_missing_prefix?(content)
    end

    test "false when the Oban block carries prefix:" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        prefix: "companyplexus",
        queues: [default: 10]
      """

      refute ObanConfig.oban_block_missing_prefix?(content)
    end

    test "a phoenix_kit prefix entry OUTSIDE the Oban block does not satisfy the check" do
      # Regression: a whole-file `prefix:` grep is satisfied by the
      # config :phoenix_kit, prefix: line the installer itself writes,
      # silencing the warning exactly when it's needed.
      content = """
      config :phoenix_kit, prefix: "companyplexus"

      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]
      """

      assert ObanConfig.oban_block_missing_prefix?(content)
    end

    test "computed prefix values count as configured" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        prefix: System.get_env("OBAN_PREFIX"),
        queues: [default: 10]
      """

      refute ObanConfig.oban_block_missing_prefix?(content)
    end

    test "false when there is no Oban block at all" do
      refute ObanConfig.oban_block_missing_prefix?("config :my_app, key: :value\n")
    end

    test "block detection stops at the next top-level config entry" do
      # prefix: in a LATER unrelated block must not count for Oban
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]

      config :other_lib, prefix: "companyplexus"
      """

      assert ObanConfig.oban_block_missing_prefix?(content)
    end

    test "a commented-out example Oban block is not a real block (no false positive)" do
      content = """
      # Example:
      # config :my_app, Oban,
      #   repo: MyApp.Repo,
      #   queues: [default: 10]

      config :my_app, MyAppWeb.Endpoint, url: [host: "localhost"]
      """

      refute ObanConfig.oban_block_missing_prefix?(content)
    end

    test "a commented block mentioning prefix: does not mask a real block lacking it" do
      # Regression: a commented-out block that happens to contain
      # `prefix:` must not satisfy the check for the genuinely active
      # Oban block below it, which lacks one.
      content = """
      # config :my_app, Oban,
      #   prefix: "example",
      #   queues: [default: 10]

      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]
      """

      assert ObanConfig.oban_block_missing_prefix?(content)
    end
  end

  describe "ensure_lifeline_plugin/2" do
    test "adds the Lifeline plugin when the plugins list has a trailing comma" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30},
        ]
      """

      updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

      assert updated =~ "{Oban.Plugins.Lifeline, rescue_after: :timer.minutes(60)}"
      # Still valid-looking: the plugin was inserted inside the same block.
      assert updated =~ ~r/plugins:\s*\[.*Oban\.Plugins\.Lifeline.*\]/s
    end

    test "adds the Lifeline plugin when the plugins list has no trailing comma" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30}
        ]
      """

      updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

      assert updated =~ "{Oban.Plugins.Lifeline, rescue_after: :timer.minutes(60)}"
    end

    test "is a no-op when the Lifeline plugin is already present" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30},
          {Oban.Plugins.Lifeline, rescue_after: :timer.minutes(60)}
        ]
      """

      assert ObanConfig.ensure_lifeline_plugin(content, "my_app") == content
    end

    test "raises an existing rescue_after that sits at or below the longest shipped worker timeout" do
      # A host that hand-wrote Lifeline, or copied Oban's own docs example
      # (:timer.minutes(5) is the "more aggressive period" sample), is in
      # exactly the window where a long job is rescued mid-flight and runs
      # twice. Presence alone is not what's worth checking.
      for minutes <- [5, 29, 30] do
        content = """
        config :my_app, Oban,
          plugins: [
            {Oban.Plugins.Lifeline, rescue_after: :timer.minutes(#{minutes})}
          ]
        """

        updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

        assert updated =~ "{Oban.Plugins.Lifeline, rescue_after: :timer.minutes(60)}"
        refute updated =~ ":timer.minutes(#{minutes})"
        assert {:ok, _} = Code.string_to_quoted(updated)
      end
    end

    test "leaves an already-safe rescue_after alone" do
      for minutes <- [31, 60, 120] do
        content = """
        config :my_app, Oban,
          plugins: [
            {Oban.Plugins.Lifeline, rescue_after: :timer.minutes(#{minutes})}
          ]
        """

        assert ObanConfig.ensure_lifeline_plugin(content, "my_app") == content
      end
    end

    test "leaves a non-:timer.minutes rescue_after expression untouched" do
      # Rewriting an expression the installer can't evaluate is how a config
      # gets corrupted — leave it and let the doctor report on the real value.
      content = """
      config :my_app, Oban,
        plugins: [
          {Oban.Plugins.Lifeline, rescue_after: @rescue_after}
        ]
      """

      assert ObanConfig.ensure_lifeline_plugin(content, "my_app") == content
    end

    test "a bare (no-opts) Oban.Plugins.Lifeline entry also counts as already present" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          Oban.Plugins.Lifeline
        ]
      """

      assert ObanConfig.ensure_lifeline_plugin(content, "my_app") == content
    end

    test "closes at the plugins-block bracket, not the Cron crontab's nested one" do
      # The real generated config always carries a Cron plugin with a
      # nested `crontab: [...]` list. A lazy match to the FIRST `]` used
      # to insert Lifeline INSIDE that list, corrupting the config
      # (review finding). The close is anchored to the `plugins:`
      # keyword's own indentation, which nested lists never share.
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        plugins: [
          {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30},
          {Oban.Plugins.Cron,
           crontab: [
             {"* * * * *", PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker}
           ]}
        ]
      """

      updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

      assert updated =~ "Oban.Plugins.Lifeline"

      # Lifeline landed as a SIBLING of Cron (after its closing `]}`),
      # not inside the crontab list.
      assert updated =~ ~r/\]\}[,]?\n\s+\{Oban\.Plugins\.Lifeline/

      refute updated =~ ~r/crontab: \[[^\]]*Lifeline/s

      # Still parseable Elixir.
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "inserted entry inherits the block's own indentation" do
      content = """
      config :my_app, Oban,
          plugins: [
            {Oban.Plugins.Pruner, max_age: 60}
          ]
      """

      updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

      # plugins: at 4 spaces -> entries at 6.
      assert updated =~ "\n      {Oban.Plugins.Lifeline"
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "leaves content unchanged when no plugins: block can be found" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]
      """

      assert ObanConfig.ensure_lifeline_plugin(content, "my_app") == content
    end

    test "rescue_after stays above every worker timeout PhoenixKit ships" do
      # Lifeline rescues purely by elapsed time and never checks whether the
      # node is still alive, so a rescue_after at or below a real job's
      # runtime re-runs that job concurrently with the still-live original
      # (duplicate deliveries, duplicate syncs). Any worker that declares a
      # longer timeout/1 — or a new long-running one — must move this value
      # up, not the other way around.
      content = """
      config :my_app, Oban,
        plugins: [
          {Oban.Plugins.Pruner, max_age: 60}
        ]
      """

      updated = ObanConfig.ensure_lifeline_plugin(content, "my_app")

      [rescue_after_minutes] =
        Regex.run(~r/rescue_after: :timer\.minutes\((\d+)\)/, updated, capture: :all_but_first)

      rescue_after = :timer.minutes(String.to_integer(rescue_after_minutes))

      # Discovered, not hardcoded: a new worker declaring a longer timeout must
      # fail this test rather than silently eroding the margin. Workers with no
      # timeout/1 return :infinity (Oban's default) and are excluded — no finite
      # rescue_after can protect an unbounded job, which is why the doc says the
      # invariant is about *declared* timeouts.
      {:ok, modules} = :application.get_key(:phoenix_kit, :modules)

      declared_timeouts =
        modules
        |> Enum.filter(&oban_worker?/1)
        |> Enum.map(&{&1, &1.timeout(%Oban.Job{})})
        |> Enum.filter(fn {_mod, timeout} -> is_integer(timeout) end)

      assert declared_timeouts != [], "expected to discover at least one worker with a timeout/1"

      {slowest, longest_worker_timeout} = Enum.max_by(declared_timeouts, &elem(&1, 1))

      assert rescue_after > longest_worker_timeout,
             "rescue_after (#{rescue_after}ms) must exceed #{inspect(slowest)}'s " <>
               "timeout/1 (#{longest_worker_timeout}ms)"
    end
  end

  describe "ensure_digest_cron_entries/2" do
    @existing_crontab """
    config :my_app, Oban,
      repo: MyApp.Repo,
      plugins: [
        {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30},
        {Oban.Plugins.Cron,
         crontab: [
           {"* * * * *", PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker}
         ]}
      ]
    """

    test "backfills every cadence into a crontab that predates the digest workers" do
      # The regression this guards: `ensure_cron_plugin/2` returns early once
      # ProcessScheduledJobsWorker is present, so without this pass an upgraded
      # host keeps a digest-less crontab — and a user picking a digest cadence
      # loses those notifications entirely (the creation path already suppresses
      # the per-event inbox row for a non-immediate cadence).
      updated = ObanConfig.ensure_digest_cron_entries(@existing_crontab, "my_app")

      for cadence <- ~w(hourly 12h daily weekly) do
        assert updated =~ ~r/DigestWorker[^\n]*cadence: "#{cadence}"/
      end

      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "entries land inside the crontab list, not beside it" do
      updated = ObanConfig.ensure_digest_cron_entries(@existing_crontab, "my_app")

      assert updated =~ ~r/crontab: \[.*DigestWorker.*\n\s+\]\}/s
      # The pre-existing entry survives.
      assert updated =~ "ProcessScheduledJobsWorker"
    end

    test "is idempotent — a fully-configured crontab is untouched" do
      once = ObanConfig.ensure_digest_cron_entries(@existing_crontab, "my_app")

      assert ObanConfig.ensure_digest_cron_entries(once, "my_app") == once
    end

    test "adds only the cadences that are missing" do
      partial = """
      config :my_app, Oban,
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             {"0 * * * *", PhoenixKit.Notifications.DigestWorker, args: %{cadence: "hourly"}}
           ]}
        ]
      """

      updated = ObanConfig.ensure_digest_cron_entries(partial, "my_app")

      # "hourly" was already there and must not be duplicated.
      assert length(Regex.scan(~r/cadence: "hourly"/, updated)) == 1

      for cadence <- ~w(12h daily weekly) do
        assert updated =~ ~r/DigestWorker[^\n]*cadence: "#{cadence}"/
      end

      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "leaves content unchanged when no crontab block can be found" do
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10]
      """

      assert ObanConfig.ensure_digest_cron_entries(content, "my_app") == content
    end

    test "every cadence it writes is one DigestWorker actually windows" do
      # Two lists that must not drift: the crontab entries the installer emits
      # and `ChannelConfig.cadences/0` (what the settings UI offers). A cadence
      # offered but never scheduled is a silently dead option.
      updated = ObanConfig.ensure_digest_cron_entries(@existing_crontab, "my_app")

      scheduled =
        ~r/DigestWorker[^\n]*cadence: "([^"]+)"/
        |> Regex.scan(updated, capture: :all_but_first)
        |> List.flatten()
        |> MapSet.new()

      digestable = MapSet.delete(MapSet.new(ChannelConfig.cadences()), "immediate")

      assert scheduled == digestable
    end
  end

  describe "ensure_cron_plugin/2 — migrating off the old posts worker" do
    defp crontab_with(worker) do
      """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             {"* * * * *", #{worker}}
           ]}
        ]
      """
    end

    test "renames the real module, which the old literal never matched" do
      # The replacement was "PhoenixKit.Posts.Workers.PublishScheduledPostsJob",
      # a module in no repo; the real one is PhoenixKitPosts.Workers.…. The
      # guard matched, the replace found nothing, and because this is cond's
      # first clause it shadowed every later case — so the core worker was
      # never added either.
      content = crontab_with("PhoenixKitPosts.Workers.PublishScheduledPostsJob")
      updated = ObanConfig.ensure_cron_plugin(content, "my_app")

      refute updated =~ "PublishScheduledPostsJob"
      assert updated =~ "PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker"
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "leaves a host that already has both alone rather than duplicating" do
      # Rewriting here would produce two identical crontab lines.
      content = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [default: 10],
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             {"* * * * *", PhoenixKitPosts.Workers.PublishScheduledPostsJob},
             {"* * * * *", PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker}
           ]}
        ]
      """

      assert ObanConfig.ensure_cron_plugin(content, "my_app") == content
    end

    test "a host already on the core worker is untouched" do
      content = crontab_with("PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker")

      assert ObanConfig.ensure_cron_plugin(content, "my_app") == content
    end
  end

  describe "ensure_scheduled_jobs_queue/2" do
    # The exact shape a host installed between 2025-12-28 and 1.7.63 still has:
    # the per-minute cron entry present, the queue it fires into absent.
    @queueless_host """
    config :my_app, Oban,
      repo: MyApp.Repo,
      queues: [
        default: 10,
        emails: 50
      ],
      plugins: [
        {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 30},
        {Oban.Plugins.Cron,
         crontab: [
           {"* * * * *", PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker}
         ]}
      ]
    """

    test "adds the queue to a host whose crontab fires into it but never ran it" do
      updated = ObanConfig.ensure_scheduled_jobs_queue(@queueless_host, "my_app")

      assert updated =~ ~r/scheduled_jobs:\s*1/
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "the crontab's worker reference alone does not count as the queue" do
      # The regression that made this helper necessary: the entry naming
      # PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker is already
      # in the file. A looser check would read that as "configured" and leave
      # the host exactly as broken as it was, silently.
      refute @queueless_host =~ ~r/scheduled_jobs:\s*\d+/

      assert ObanConfig.ensure_scheduled_jobs_queue(@queueless_host, "my_app") !=
               @queueless_host
    end

    test "leaves an already-configured queue alone" do
      configured = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [
          default: 10,
          scheduled_jobs: 1
        ]
      """

      assert ObanConfig.ensure_scheduled_jobs_queue(configured, "my_app") == configured
    end

    test "does not double up when run twice" do
      once = ObanConfig.ensure_scheduled_jobs_queue(@queueless_host, "my_app")
      twice = ObanConfig.ensure_scheduled_jobs_queue(once, "my_app")

      assert once == twice
      assert length(Regex.scan(~r/scheduled_jobs:\s*\d+/, twice)) == 1
    end

    test "a queues block that already ends in a comma does not gain a second one" do
      trailing = """
      config :my_app, Oban,
        repo: MyApp.Repo,
        queues: [
          default: 10,
        ]
      """

      updated = ObanConfig.ensure_scheduled_jobs_queue(trailing, "my_app")

      refute updated =~ ",,"
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "leaves content untouched when there is no queues block to parse" do
      no_queues = "config :my_app, Oban, repo: MyApp.Repo\n"

      assert ObanConfig.ensure_scheduled_jobs_queue(no_queues, "my_app") == no_queues
    end

    test "a commented-out entry does not count as configured" do
      # The nastiest shape available, because this function's own failure path
      # prints "Please manually add: scheduled_jobs: 1" — so the line a host
      # pastes in to remind itself is exactly what a whole-file match would
      # read as "already done", leaving it broken with no output saying so.
      commented = """
      config :my_app, Oban,
        queues: [
          default: 10
          # scheduled_jobs: 1
        ]
      """

      updated = ObanConfig.ensure_scheduled_jobs_queue(commented, "my_app")

      refute updated == commented
      assert updated =~ ~r/^\s*scheduled_jobs: 1/m
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "the keyword form of the queue counts as configured" do
      # `scheduled_jobs: [limit: 1]` is the same queue. Appending a second
      # entry gives the config a duplicate key, which parses — so nothing here
      # would notice — and then Oban.Midwife's `{:ok, _} = start_queue(...)`
      # raises on the second start and the host does not boot.
      keyword_form = """
      config :my_app, Oban,
        queues: [
          default: 10,
          scheduled_jobs: [limit: 1]
        ]
      """

      assert ObanConfig.ensure_scheduled_jobs_queue(keyword_form, "my_app") == keyword_form
    end

    test "never writes the queue into a neighbouring application's config" do
      # An Oban block with no `queues:` of its own used to let the scan run
      # past the end of the block and add the queue to whatever came next.
      other_app = """
      config :my_app, Oban,
        repo: MyApp.Repo

      config :other_app, OtherThing,
        queues: [
          alpha: 5
        ]
      """

      assert ObanConfig.ensure_scheduled_jobs_queue(other_app, "my_app") == other_app
    end

    test "an entry with nested options keeps the insert at the outer level" do
      # `default: [limit: 10]` is legal. Stopping at the first `]` would put
      # the queue inside it, producing an option Oban rejects at boot — and
      # the result parses, so only reading it catches the mistake.
      nested = """
      config :my_app, Oban,
        queues: [
          default: [
            limit: 10
          ],
          emails: 50
        ]
      """

      updated = ObanConfig.ensure_scheduled_jobs_queue(nested, "my_app")

      assert {:ok, _} = Code.string_to_quoted(updated)

      # Indentation is the tell: a sibling of `emails:` (4 spaces) is in the
      # queues list; a sibling of `limit:` (6) is inside `default:`.
      assert updated =~ ~r/^    emails: 50,\n    scheduled_jobs: 1$/m
      assert updated =~ "default: [\n      limit: 10\n    ],"
    end

    test "an empty queues list is left alone rather than given a queue" do
      # Oban documents `[]` as equivalent to `false` — "prevents any queues
      # from starting on init". A node that says it runs nothing should not be
      # handed a queue, and the old scan corrupted these anyway: `queues: []`
      # ran on into the plugins block, and `queues: [\n]` wrote `queues: [,`.
      for empty <- [
            "config :my_app, Oban,\n  queues: [],\n  plugins: [\n    {Oban.Plugins.Pruner, max_age: 60}\n  ]\n",
            "config :my_app, Oban,\n  queues: [\n  ]\n"
          ] do
        assert ObanConfig.ensure_scheduled_jobs_queue(empty, "my_app") == empty
      end
    end
  end

  describe "ensure_queue/4 — the hardening applies to every queue, not just one" do
    # ensure_scheduled_jobs_queue/2 was written hardened against six ways
    # string surgery on a queues list goes wrong. The six sibling helpers that
    # predated it each hand-rolled the same surgery and reproduced every one of
    # those defects — and a bad insert is worse than the missing queue it was
    # trying to add, because it corrupts the host's config.exs. They now share
    # this implementation; these tests are what stops one drifting back out.

    @queueless """
    config :my_app, Oban,
      repo: MyApp.Repo,
      queues: [
        default: 10,
        emails: 50
      ]
    """

    test "every queue the installer manages inserts into a real host config" do
      for {queue, limit} <- [
            {"posts", 10},
            {"sitemap", 5},
            {"shop_imports", 2},
            {"newsletters_delivery", 10},
            {"catalogue_pdf", 2},
            {"notifications", 10},
            {"scheduled_jobs", 1}
          ] do
        updated = ObanConfig.ensure_queue(@queueless, "my_app", queue, limit)

        assert updated =~ ~r/^\s*#{queue}: #{limit}$/m, queue
        assert {:ok, _} = Code.string_to_quoted(updated)
        assert ObanConfig.ensure_queue(updated, "my_app", queue, limit) == updated, queue
      end
    end

    test "a key merely ENDING in the queue's name does not count as configured" do
      # The sibling check was an unanchored ~r/notifications:\s*\d+/, so a
      # host's own `push_notifications: 5` satisfied it and the real
      # `notifications` queue was never added — the exact silent-missing-queue
      # failure the scheduled_jobs incident was about, one guard further up.
      host = """
      config :my_app, Oban,
        queues: [
          default: 10,
          push_notifications: 5
        ]
      """

      updated = ObanConfig.ensure_queue(host, "my_app", "notifications", 10)

      assert updated =~ ~r/^\s*notifications: 10$/m
      assert updated =~ "push_notifications: 5"
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "a commented-out entry does not count as configured" do
      commented = """
      config :my_app, Oban,
        queues: [
          default: 10
          # posts: 10
        ]
      """

      updated = ObanConfig.ensure_queue(commented, "my_app", "posts", 10)

      assert updated =~ ~r/^\s*posts: 10$/m
      assert {:ok, _} = Code.string_to_quoted(updated)
    end

    test "the keyword form counts as configured, so no duplicate key is written" do
      # A duplicate key parses, survives normalize_queues/1, and then
      # Oban.Midwife's `{:ok, _} = start_queue(...)` raises on the second
      # start — the host does not boot.
      keyword_form = """
      config :my_app, Oban,
        queues: [
          default: 10,
          sitemap: [limit: 5]
        ]
      """

      assert ObanConfig.ensure_queue(keyword_form, "my_app", "sitemap", 5) == keyword_form
    end

    test "never writes into a neighbouring application's config" do
      other_app = """
      config :my_app, Oban,
        repo: MyApp.Repo

      config :other_app, OtherThing,
        queues: [
          alpha: 5
        ]
      """

      assert ObanConfig.ensure_queue(other_app, "my_app", "posts", 10) == other_app
    end

    test "an entry with nested options keeps the insert at the outer level" do
      nested = """
      config :my_app, Oban,
        queues: [
          default: [
            limit: 10
          ],
          emails: 50
        ]
      """

      updated = ObanConfig.ensure_queue(nested, "my_app", "catalogue_pdf", 2)

      assert {:ok, _} = Code.string_to_quoted(updated)
      assert updated =~ ~r/^    emails: 50,\n    catalogue_pdf: 2$/m
      assert updated =~ "default: [\n      limit: 10\n    ],"
    end

    test "a queues list ending in a comment keeps the comma out of the comment" do
      trailing_comment = """
      config :my_app, Oban,
        queues: [
          default: 10
          # keep this list alphabetical
        ]
      """

      updated = ObanConfig.ensure_queue(trailing_comment, "my_app", "posts", 10)

      assert {:ok, _} = Code.string_to_quoted(updated)
      assert updated =~ "default: 10,"
      assert updated =~ "# keep this list alphabetical"
    end

    test "an empty queues list is left alone rather than given a queue" do
      for empty <- [
            "config :my_app, Oban,\n  queues: [],\n  plugins: [\n    {Oban.Plugins.Pruner, max_age: 60}\n  ]\n",
            "config :my_app, Oban,\n  queues: [\n  ]\n"
          ] do
        assert ObanConfig.ensure_queue(empty, "my_app", "posts", 10) == empty
      end
    end
  end

  defp oban_worker?(module) do
    Code.ensure_loaded?(module) and
      function_exported?(module, :timeout, 1) and
      module.__info__(:attributes)
      |> Keyword.get_values(:behaviour)
      |> List.flatten()
      |> Enum.member?(Oban.Worker)
  end
end
