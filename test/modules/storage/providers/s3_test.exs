defmodule PhoenixKit.Modules.Storage.Providers.S3ResolveCredentialsTest do
  @moduledoc """
  `Providers.S3.resolve_credentials/1` — the one place a bucket's actual
  (plaintext) S3 credentials get produced, either by decrypting
  `secret_access_key` or by reading through a `PhoenixKit.Integrations`
  connection. `@doc false` and public for exactly this: testable without a
  real S3 endpoint (same rationale as `V174.repair_statements/1`).
  """
  # async: false — setup below stamps the global `:phoenix_kit,
  # :secret_key_base` app env, which other concurrently-running async tests
  # could observe mid-test. Same rationale as PhoenixKit.Integrations.EncryptionTest.
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Modules.Storage.Bucket
  alias PhoenixKit.Modules.Storage.Providers.S3

  setup do
    original = Application.get_env(:phoenix_kit, :secret_key_base)
    Application.put_env(:phoenix_kit, :secret_key_base, "test-secret-for-s3-resolve")

    on_exit(fn ->
      if original,
        do: Application.put_env(:phoenix_kit, :secret_key_base, original),
        else: Application.delete_env(:phoenix_kit, :secret_key_base)
    end)

    :ok
  end

  describe "direct credentials (no integration_uuid)" do
    test "decrypts an encrypted secret_access_key" do
      bucket = %Bucket{
        access_key_id: "AKIAEXAMPLE",
        secret_access_key: Encryption.encrypt_value("super-secret-value")
      }

      assert S3.resolve_credentials(bucket) == {"AKIAEXAMPLE", "super-secret-value"}
    end

    test "passes through a plaintext secret_access_key (e.g. the test_connection flow, which never persists through the changeset)" do
      bucket = %Bucket{access_key_id: "AKIAEXAMPLE", secret_access_key: "raw-plaintext"}

      assert S3.resolve_credentials(bucket) == {"AKIAEXAMPLE", "raw-plaintext"}
    end

    test "returns a nil secret when decryption fails (corrupted/undecryptable ciphertext)" do
      bucket = %Bucket{
        access_key_id: "AKIAEXAMPLE",
        secret_access_key: "enc:v1:not-valid-base64!!"
      }

      assert S3.resolve_credentials(bucket) == {"AKIAEXAMPLE", nil}
    end

    test "nil secret_access_key resolves to a nil secret" do
      bucket = %Bucket{access_key_id: "AKIAEXAMPLE", secret_access_key: nil}

      assert S3.resolve_credentials(bucket) == {"AKIAEXAMPLE", nil}
    end
  end

  describe "integration_uuid" do
    test "resolves access_key/secret_key from the referenced Integrations connection" do
      {:ok, %{uuid: uuid}} = Integrations.add_connection("aws_ses", "test bucket integration")

      {:ok, _} =
        Integrations.save_setup(uuid, %{
          "access_key" => "AKIAFROMINTEGRATION",
          "secret_key" => "secret-from-integration",
          "aws_region" => "us-east-1"
        })

      bucket = %Bucket{integration_uuid: uuid, access_key_id: nil, secret_access_key: nil}

      assert S3.resolve_credentials(bucket) ==
               {"AKIAFROMINTEGRATION", "secret-from-integration"}
    end

    test "returns {nil, nil} for a connection owned by a user: a bucket reads only its own owner's" do
      # An arbitrary owner uuid: owner_uuid is a stored string, no FK.
      owner = {:user, UUIDv7.generate()}

      {:ok, %{uuid: uuid}} =
        Integrations.add_connection("object_storage", "personal", nil, owner: owner)

      {:ok, _} =
        Integrations.save_setup(
          uuid,
          %{"access_key" => "AKIAPERSONAL", "secret_key" => "personal-secret"},
          nil,
          owner: owner
        )

      bucket = %Bucket{integration_uuid: uuid}

      assert S3.resolve_credentials(bucket) == {nil, nil}
    end

    test "returns {nil, nil} when the integration_uuid does not resolve to a connected integration" do
      ghost_uuid = "00000000-0000-7000-8000-000000000000"
      bucket = %Bucket{integration_uuid: ghost_uuid}

      assert S3.resolve_credentials(bucket) == {nil, nil}
    end
  end

  describe "upload_content_type/2 (#951)" do
    test "the caller's type wins" do
      assert S3.upload_content_type([content_type: "image/avif"], "a/b/photo.jpg") == "image/avif"
    end

    test "without one, the key's extension decides, so a copy between buckets is not octet-stream" do
      assert S3.upload_content_type([], "ab/cd/abcd_original.jpg") == "image/jpeg"
      assert S3.upload_content_type([], "ab/cd/abcd_large.webp") == "image/webp"
      assert S3.upload_content_type([acl: "public-read"], "x/y.png") == "image/png"
    end

    test "an unknown extension is application/octet-stream, as S3 would have served it" do
      assert S3.upload_content_type([], "x/y.unknownext") == "application/octet-stream"
    end
  end

  describe "signed_download_url/3" do
    @opts [disposition: ~s(attachment; filename="a b.html"), content_type: "text/html"]

    test "signs a path-style URL on a custom endpoint that overrides the response headers" do
      bucket = %Bucket{
        name: "r2",
        bucket_name: "media",
        region: "auto",
        endpoint: "acct.r2.cloudflarestorage.com",
        access_key_id: "AKIAEXAMPLE",
        secret_access_key: "raw-plaintext"
      }

      assert {:ok, url} = S3.signed_download_url(bucket, "ab/cd/abcd_original.html", @opts)

      uri = URI.parse(url)
      query = URI.decode_query(uri.query)

      assert uri.scheme == "https"
      assert uri.host == "acct.r2.cloudflarestorage.com"
      assert uri.path == "/media/ab/cd/abcd_original.html"
      assert query["response-content-disposition"] == ~s(attachment; filename="a b.html")
      assert query["response-content-type"] == "text/html"
      assert query["X-Amz-Expires"] == "3600"
      assert query["X-Amz-Signature"] =~ ~r/^[0-9a-f]{64}$/
    end

    test "an AWS bucket signs against its regional host" do
      bucket = %Bucket{
        name: "aws",
        bucket_name: "media",
        region: "eu-central-1",
        access_key_id: "AKIAEXAMPLE",
        secret_access_key: "raw-plaintext"
      }

      assert {:ok, url} = S3.signed_download_url(bucket, "k.zip", expires_in: 60)
      assert URI.parse(url).host =~ "eu-central-1"
      assert URI.decode_query(URI.parse(url).query)["X-Amz-Expires"] == "60"
    end

    test "without usable credentials there is no URL, so the caller proxies" do
      bucket = %Bucket{name: "b", bucket_name: "media", access_key_id: "AKIAEXAMPLE"}

      assert S3.signed_download_url(bucket, "k.zip", @opts) == {:error, :no_credentials}
    end
  end
end
