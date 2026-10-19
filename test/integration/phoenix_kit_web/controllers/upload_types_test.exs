defmodule PhoenixKitWeb.UploadTypesTest do
  @moduledoc """
  What `POST /api/upload` takes: the raster types the image pipeline renders
  (an iPhone's HEIC and HEIF among them, which it used to turn away as "not
  allowed"), nothing executable, and a size cap that is the site's
  `storage_max_upload_size_mb` setting, not a fixed number.
  """
  use PhoenixKit.DataCase, async: false

  import Plug.Test, only: [conn: 2]

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKitWeb.UploadController

  setup do
    {:ok, seed} =
      Auth.register_user(%{
        email: "seed-#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    {:ok, _} = Auth.admin_confirm_user(seed)

    {:ok, user} =
      Auth.register_user(%{
        email: "uploader-#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    user = Repo.get!(Auth.User, user.uuid)

    dir = Path.join(System.tmp_dir!(), "pk_upload_types_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    %{user: user, dir: dir}
  end

  defp upload(ctx, content_type, bytes \\ "not really a picture", name \\ "a.bin") do
    path = Path.join(ctx.dir, "u#{System.unique_integer([:positive])}")
    File.write!(path, bytes)

    conn =
      conn(:post, "/api/upload")
      |> Plug.Conn.assign(:phoenix_kit_current_user, ctx.user)
      |> Plug.Conn.put_req_header("x-forwarded-for", "10.0.0.#{:rand.uniform(200)}")

    conn =
      UploadController.create(conn, %{
        "file" => %Plug.Upload{path: path, filename: name, content_type: content_type}
      })

    {conn.status, Jason.decode!(conn.resp_body)}
  end

  describe "types" do
    test "the image types the pipeline renders are not turned away", ctx do
      for {type, name} <- [
            {"image/heic", "IMG_1.heic"},
            {"image/heif", "IMG_2.heif"},
            {"image/avif", "a.avif"},
            {"image/tiff", "a.tiff"},
            {"image/bmp", "a.bmp"}
          ] do
        {_status, body} = upload(ctx, type, "bytes", name)
        refute body["error"] == "INVALID_FILE_TYPE", "#{type} was refused as not allowed"
      end
    end

    test "what was always taken still is", ctx do
      for type <-
            ~w(image/jpeg image/png image/webp image/gif video/mp4 video/webm video/quicktime application/pdf) do
        {_status, body} = upload(ctx, type)
        refute body["error"] == "INVALID_FILE_TYPE", "#{type} was refused as not allowed"
      end
    end

    test "nothing executable, or unknown, is", ctx do
      for type <- [
            "application/x-msdownload",
            "text/html",
            "application/x-sh",
            "",
            "image/svg+xml"
          ] do
        assert {400, %{"error" => "INVALID_FILE_TYPE"}} = upload(ctx, type)
      end
    end
  end

  describe "size" do
    test "the cap is the site's setting", ctx do
      {:ok, _} = Settings.update_setting("storage_max_upload_size_mb", "1")
      two_mib = :binary.copy("x", 2 * 1_048_576)

      assert {413, %{"error" => "FILE_TOO_LARGE", "message" => message}} =
               upload(ctx, "image/jpeg", two_mib)

      assert message =~ "1"

      {:ok, _} = Settings.update_setting("storage_max_upload_size_mb", "5")
      {_status, body} = upload(ctx, "image/jpeg", two_mib)
      refute body["error"] == "FILE_TOO_LARGE"
    end
  end
end
