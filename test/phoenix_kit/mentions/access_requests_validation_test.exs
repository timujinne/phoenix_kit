defmodule PhoenixKit.Mentions.AccessRequestsValidationTest do
  @moduledoc """
  Unit tests for the pre-insert guards on `AccessRequests.request/4`.

  These paths must not reach the database — they reject forged type/uuid
  payloads and rate-limited accounts before any insert is attempted. No
  PostgreSQL required.
  """

  use ExUnit.Case, async: true

  alias PhoenixKit.Mentions.AccessRequests

  @requester "0193a5e4-0000-7000-8000-000000000001"
  # A well-formed uuid that is not a registered resource type's target.
  @target "0193a5e4-0000-7000-8000-000000000099"

  test "rejects a free-form resource_type that no module has registered" do
    assert {:error, :unknown_resource_type} =
             AccessRequests.request("not_a_real_type", @target, @requester)
  end

  test "rejects an empty resource_type" do
    assert {:error, :invalid_resource} = AccessRequests.request("", @target, @requester)
  end

  test "rejects an oversized resource_type" do
    type = String.duplicate("x", 101)

    assert {:error, :invalid_resource} = AccessRequests.request(type, @target, @requester)
  end

  test "rejects a non-uuid resource_uuid" do
    # "user" is always registered by ResourceLinks, so a garbage uuid is
    # the half that must fail closed rather than cast-error on insert.
    assert {:error, :invalid_resource} =
             AccessRequests.request("user", "not-a-uuid", @requester)
  end
end
