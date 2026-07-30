defmodule PhoenixKitWeb.Components.Core.EmailActivityBadgesTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.EmailActivityBadges

  # Every status accepted by PhoenixKit.Modules.Emails.Log's changeset. The
  # component's failure list is the failing subset of exactly this vocabulary,
  # so the two are asserted against each other below rather than trusted to
  # stay in sync by eye.
  @all_statuses ~w(queued sent delivered bounced hard_bounced soft_bounced opened
                   clicked failed rejected delayed complaint)

  @failure_statuses ~w(bounced hard_bounced soft_bounced failed rejected complaint)
  @non_failure_statuses @all_statuses -- @failure_statuses

  # A log whose status is set but whose timestamps and events are all empty —
  # the shape a writer leaves behind when it records the status without the
  # matching timestamp. No timestamps also means no Settings lookup, so these
  # stay DB-free unit tests.
  defp log(status) do
    %{
      status: status,
      events: nil,
      queued_at: nil,
      sent_at: nil,
      delivered_at: nil,
      opened_at: nil,
      clicked_at: nil,
      bounced_at: nil,
      rejected_at: nil,
      delayed_at: nil,
      complained_at: nil,
      failed_at: nil
    }
  end

  defp render(log) do
    assigns = %{log: log}
    rendered_to_string(~H|<.email_activity_badges log={@log} />|)
  end

  defp badge_count(html), do: html |> String.split("badge badge-") |> length() |> Kernel.-(1)

  describe "a failure status with no timestamp behind it" do
    test "every failure status still renders a badge" do
      # The bug this covers: with the meaning carried by colour alone, a
      # timestamp-less failure rendered as the plain blue "sent" badge, so the
      # list claimed a message went out that the detail page reports as failed.
      for status <- @failure_statuses do
        html = render(log(status))

        assert badge_count(html) == 1, "expected exactly one badge for #{status}: #{html}"
        refute html =~ "badge-info", "#{status} must never render as sent"
      end
    end

    test "complaint is spelled the way writers spell it" do
      # SqsProcessor writes status: "complaint"; the first version of this list
      # said "complained", so spam complaints kept rendering as sent.
      assert render(log("complaint")) =~ "badge-error"
      assert render(log("complaint")) =~ "Complaint"
    end

    test "the badge colour matches the status badge on the detail page" do
      # A soft bounce is retryable and stays amber in EmailStatusBadge; painting
      # it red here would contradict the same log's status badge.
      assert render(log("soft_bounced")) =~ "badge-warning"
      refute render(log("soft_bounced")) =~ "badge-error"

      assert render(log("hard_bounced")) =~ "badge-error"
      assert render(log("failed")) =~ "badge-error"
    end

    test "the badge is labelled, since there is no timestamp to show" do
      assert render(log("hard_bounced")) =~ "Hard Bounced"
      assert render(log("soft_bounced")) =~ "Soft Bounced"
      assert render(log("rejected")) =~ "Rejected"
    end
  end

  describe "statuses that are not failures" do
    test "render no status-only badge" do
      for status <- @non_failure_statuses do
        html = render(log(status))

        assert badge_count(html) == 0,
               "#{status} is not a failure and must not get a status-only badge: #{html}"
      end
    end

    test "a delayed send is not treated as a failure" do
      # `delayed` is amber in EmailStatusBadge but the send is still in flight.
      assert badge_count(render(log("delayed"))) == 0
    end

    test "an unknown status is ignored rather than guessed at" do
      assert badge_count(render(log("something_new"))) == 0
      assert badge_count(render(log(nil))) == 0
    end
  end

  describe "no duplicate badge" do
    test "a failure already backed by an event is not repeated" do
      # The status-only badge exists to cover a MISSING event, so an event that
      # is present must win outright. Compared on event type, not colour: a soft
      # bounce event is amber, which a colour check would miss.
      for {status, event_type} <- [
            {"failed", "failed"},
            {"hard_bounced", "bounce"},
            {"soft_bounced", "bounce"},
            {"complaint", "complaint"},
            {"rejected", "rejected"}
          ] do
        occurred_at = ~U[2026-07-29 09:15:00Z]
        log = %{log(status) | events: [%{event_type: event_type, occurred_at: occurred_at}]}
        html = render(log)

        assert badge_count(html) == 1,
               "#{status} with a #{event_type} event should render one badge: #{html}"
      end
    end
  end
end
