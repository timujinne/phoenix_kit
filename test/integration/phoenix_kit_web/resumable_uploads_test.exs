defmodule PhoenixKitWeb.ResumableUploadsTest do
  @moduledoc """
  The server half of camera-proof uploads: a host LiveView with two ordinary
  `allow_upload`s switched to `allow_resumable_upload`, driven the way the
  `ResumableUpload` hook drives it (`pk_upload_pick`, `pk_upload_resume`, the
  buttons) and by LiveViewTest's own upload client.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias Phoenix.HTML.Safe
  alias PhoenixKit.Modules.Storage
  alias PhoenixKitWeb.Components.Core.ResumableUpload
  alias PhoenixKitWeb.Components.MediaBrowser
  alias PhoenixKitWeb.ResumableUploads

  defmodule FailingWriter do
    @moduledoc false
    @behaviour Phoenix.LiveView.UploadWriter

    def init(_opts), do: {:ok, %{}}
    def meta(state), do: state
    def write_chunk(_data, state), do: {:error, :disk_full, state}
    def close(state, _reason), do: {:ok, state}
  end

  defmodule Host do
    @moduledoc false
    use Phoenix.LiveView

    import PhoenixKitWeb.Components.Core.ResumableUpload
    import PhoenixKitWeb.ResumableUploads, only: [allow_resumable_upload: 4]

    def mount(_params, session, socket) do
      opts = Application.get_env(:phoenix_kit, :resumable_uploads_test_opts, [])
      _ = session

      {:ok,
       socket
       |> allow_resumable_upload(
         :photos,
         [accept: :any, max_entries: 2, max_file_size: 20, auto_upload: true],
         opts
       )
       |> allow_resumable_upload(:docs, [accept: :any, max_entries: 2, auto_upload: true], [])
       |> allow_resumable_upload(
         :flaky,
         [
           accept: :any,
           max_entries: 2,
           auto_upload: true,
           writer: fn _name, _entry, _socket ->
             {PhoenixKitWeb.ResumableUploadsTest.FailingWriter, []}
           end
         ],
         []
       )
       |> Phoenix.Component.assign(saved: [], pending: false, order: "order-1")}
    end

    def render(assigns) do
      ~H"""
      <form id="f" phx-change="validate" phx-submit="save">
        <.resumable_upload
          upload={@uploads.photos}
          resumable={@resumable_uploads}
          scope={"rec|" <> @order}
          user="u1"
          context="folder-a"
        >
          <.live_file_input upload={@uploads.photos} />
        </.resumable_upload>
        <.resumable_upload
          upload={@uploads.docs}
          resumable={@resumable_uploads}
          scope={"rec|" <> @order}
          user="u1"
        >
          <.live_file_input upload={@uploads.docs} />
        </.resumable_upload>
        <.live_file_input upload={@uploads.flaky} />
      </form>
      <p :for={s <- @saved} class="saved">{s}</p>
      <span :if={@pending} id="pending">pending</span>
      """
    end

    def handle_event("validate", _params, socket), do: {:noreply, socket}

    def handle_event("cancel", %{"ref" => ref}, socket),
      do: {:noreply, cancel_upload(socket, :photos, ref)}

    def handle_event("check", _params, socket) do
      {:noreply,
       Phoenix.Component.assign(
         socket,
         :pending,
         PhoenixKitWeb.ResumableUploads.pending?(socket, :photos)
       )}
    end

    # `bad.png` is refused for good, `later.png` fails for now, the rest is saved
    # with the context the browser stored for it.
    def handle_event("save", _params, socket) do
      {socket, saved} =
        PhoenixKitWeb.ResumableUploads.consume_uploaded_entries(socket, :photos, fn _meta,
                                                                                    entry ->
          context = PhoenixKitWeb.ResumableUploads.resume_context(socket, entry)

          case entry.client_name do
            "bad.png" -> {:rejected, nil}
            "later.png" -> {:retry, nil}
            name -> {:stored, "#{name}@#{context}"}
          end
        end)

      {:noreply,
       Phoenix.Component.assign(
         socket,
         :saved,
         socket.assigns.saved ++ Enum.reject(saved, &is_nil/1)
       )}
    end
  end

  defp host(conn, session \\ %{}), do: live_isolated(conn, Host, session: session)

  defp upload(view, name, upload \\ :photos, content \\ "12345") do
    file_input(view, "#f", upload, [
      %{name: name, content: content, type: "image/png", last_modified: 7}
    ])
  end

  defp key(name, content \\ "12345"), do: "#{name}|#{byte_size(content)}|7"

  defp item(name, extra \\ %{}) do
    Map.merge(
      %{
        "id" => "id-" <> name,
        "key" => key(name),
        "seq" => "s-" <> name,
        "name" => name,
        "size" => 5,
        "context" => "folder-a",
        "has_bytes" => true,
        "state" => "pending",
        "attempts" => 0,
        "fresh" => true
      },
      extra
    )
  end

  defp resume(view, items, upload \\ "photos") do
    render_hook(view, "pk_upload_resume", %{"upload" => upload, "items" => items})
  end

  describe "the component" do
    test "renders the hook element with its data attributes", %{conn: conn} do
      {:ok, view, _} = host(conn)
      el = element(view, ~s([phx-hook="ResumableUpload"][data-upload="photos"]))
      assert has_element?(el)
      html = render(el)
      assert html =~ ~s(data-scope="rec|order-1")
      assert html =~ ~s(data-user="u1")
      assert html =~ ~s(data-context="folder-a")
      assert html =~ ~s(data-fresh-ms="1800000")
      assert has_element?(view, ~s([phx-hook="ResumableUpload"][data-upload="docs"]))
    end

    test "an upload that was not set up logs and still renders its input" do
      import ExUnit.CaptureLog

      log =
        capture_log(fn ->
          html =
            %{
              upload: %Phoenix.LiveView.UploadConfig{name: :loose},
              resumable: %{},
              scope: "x",
              user: "u",
              context: "",
              fresh_ms: 0,
              watch: "self",
              class: nil,
              inner_block: [%{__slot__: :inner_block, inner_block: fn _, _ -> "inner" end}],
              __changed__: nil
            }
            |> ResumableUpload.resumable_upload()
            |> Safe.to_iodata()
            |> IO.iodata_to_binary()

          assert html =~ "inner"
          refute html =~ "ResumableUpload"
        end)

      assert log =~ "not set up with allow_resumable_upload"
    end
  end

  describe "events" do
    test "an event for an upload nobody attached is answered, not crashed on", %{conn: conn} do
      {:ok, view, _} = host(conn)
      render_hook(view, "pk_upload_resume", %{"upload" => "ghost", "items" => []})
      assert_reply(view, %{error: "not_attached"})
      assert Process.alive?(view.pid)
    end

    test "pk_upload_debug is logged as counts, answered and kept from the host", %{conn: conn} do
      import ExUnit.CaptureLog
      {:ok, view, _} = host(conn)
      previous = Logger.level()
      Logger.configure(level: :info)
      on_exit(fn -> Logger.configure(level: previous) end)

      log =
        capture_log([level: :info], fn ->
          render_hook(view, "pk_upload_debug", %{
            "upload" => "photos",
            "phase" => "scan",
            "n" => 2,
            "connected" => true,
            "name" => "secret.png"
          })
        end)

      assert log =~ "photos scan n=2 connected=true"
      refute log =~ "secret"
      assert_reply(view, %{})
      assert Process.alive?(view.pid)
    end

    test "events of one upload do not touch the other", %{conn: conn} do
      {:ok, view, _} = host(conn)

      render_hook(view, "pk_upload_pick", %{
        "upload" => "docs",
        "items" => [%{"key" => key("a.png"), "seq" => "1", "context" => "docs-ctx"}]
      })

      input = upload(view, "a.png")
      render_upload(input, "a.png")
      render_submit(element(view, "#f"))
      assert render(view) =~ "a.png@"
      refute render(view) =~ "docs-ctx"
    end
  end

  describe "the context of a pick" do
    test "comes back at consume time, for the entry it was picked for", %{conn: conn} do
      {:ok, view, _} = host(conn)

      render_hook(view, "pk_upload_pick", %{
        "upload" => "photos",
        "items" => [%{"key" => key("a.png"), "seq" => "1", "context" => "folder-x"}]
      })

      render_upload(upload(view, "a.png"), "a.png")
      render_submit(element(view, "#f"))
      assert render(view) =~ "a.png@folder-x"
    end

    test "is nil for the same file picked twice with different contexts, and for none", %{
      conn: conn
    } do
      {:ok, view, _} = host(conn)

      render_hook(view, "pk_upload_pick", %{
        "upload" => "photos",
        "items" => [
          %{"key" => key("a.png"), "seq" => "1", "context" => "one"},
          %{"key" => key("a.png"), "seq" => "2", "context" => "two"}
        ]
      })

      render_upload(upload(view, "a.png"), "a.png")
      render_upload(upload(view, "b.png"), "b.png")
      render_submit(element(view, "#f"))
      html = render(view)
      assert html =~ "a.png@"
      refute html =~ "a.png@one"
      refute html =~ "a.png@two"
      assert html =~ "b.png@"
    end

    test "oversized strings and too many items are dropped", %{conn: conn} do
      {:ok, view, _} = host(conn)
      huge = String.duplicate("x", 600)

      items =
        [%{"key" => huge, "seq" => "1", "context" => "c"}] ++
          for i <- 1..30, do: %{"key" => "f#{i}|1|7", "seq" => "#{i}", "context" => "c"}

      render_hook(view, "pk_upload_pick", %{"upload" => "photos", "items" => items})
      assert Process.alive?(view.pid)
    end
  end

  describe "acknowledgements" do
    test "received when the bytes are in, stored when the host saved, not before", %{conn: conn} do
      {:ok, view, _} = host(conn)
      k = key("a.png")
      input = upload(view, "a.png")
      render_upload(input, "a.png")
      assert_push_event(view, "pk-upload-received", %{upload: "photos", key: ^k})

      render_submit(element(view, "#f"))
      assert_push_event(view, "pk-upload-stored", %{upload: "photos", key: ^k})
    end

    test "a final refusal sends rejected, a temporary failure sends nothing", %{conn: conn} do
      {:ok, view, _} = host(conn)
      bad = key("bad.png")
      later = key("later.png")
      render_upload(upload(view, "bad.png"), "bad.png")
      render_upload(upload(view, "later.png"), "later.png")
      render_submit(element(view, "#f"))

      assert_push_event(view, "pk-upload-rejected", %{key: ^bad})
      assert_push_event(view, "pk-upload-received", %{key: ^later})
      refute_push_event(view, "pk-upload-stored", %{key: ^later}, 50)
      refute_push_event(view, "pk-upload-rejected", %{key: ^later}, 50)
    end

    test "a refused entry (too large) is reported, flashed and frees its slot", %{conn: conn} do
      {:ok, view, _} = host(conn)
      big = String.duplicate("x", 40)
      k = key("big.png", big)

      input = upload(view, "big.png", :photos, big)
      assert {:error, _} = render_upload(input, "big.png")
      assert_push_event(view, "pk-upload-rejected", %{upload: "photos", key: ^k})
      assert :sys.get_state(view.pid).socket.assigns.flash["error"] =~ "file too large"
      assert socket_entries(view) == []
    end

    test "stored/3 and rejected/3 can be called by hand with a key", %{conn: conn} do
      {:ok, view, _} = host(conn)
      socket = %Phoenix.LiveView.Socket{private: %{live_temp: %{}}, assigns: %{__changed__: %{}}}
      socket = ResumableUploads.stored(socket, :photos, "k|1|2")
      socket = ResumableUploads.rejected(socket, :photos, "k|1|2")

      assert [["pk-upload-rejected", _], ["pk-upload-stored", _]] =
               socket.private.live_temp.push_events

      assert Process.alive?(view.pid)
    end
  end

  describe "pk_upload_resume" do
    test "a pending file with its bytes carries on by itself", %{conn: conn} do
      {:ok, view, _} = host(conn)
      resume(view, [item("a.png")])
      assert_reply(view, %{auto: ["id-a.png"], queued: [], ask: [], drop: []})
    end

    test "a received file, a file without bytes and a stale one are asked about", %{conn: conn} do
      {:ok, view, _} = host(conn)

      resume(view, [
        item("recv.png", %{"state" => "received"}),
        item("nobytes.png", %{"has_bytes" => false}),
        item("stale.png", %{"fresh" => false}),
        item("tried.png", %{"attempts" => 3})
      ])

      assert_reply(view, %{auto: [], ask: ask})

      assert Enum.sort(ask) ==
               Enum.sort(["id-recv.png", "id-nobytes.png", "id-stale.png", "id-tried.png"])

      assert has_element?(view, "#pk-resumable-photos-#{:erlang.phash2("rec|order-1")}-ask")
    end

    test "no more automatic files than free slots; the rest wait", %{conn: conn} do
      {:ok, view, _} = host(conn)
      resume(view, for(n <- ~w(a b c), do: item("#{n}.png")))
      assert_reply(view, %{auto: ["id-a.png", "id-b.png"], queued: ["id-c.png"]})
    end

    test "an entry already in flight with the same key is not fed twice", %{conn: conn} do
      {:ok, view, _} = host(conn)
      upload(view, "a.png") |> render_upload("a.png", 10)
      resume(view, [item("a.png")])
      assert_reply(view, %{auto: [], queued: ["id-a.png"]})
    end

    test "an upload with open slots taken by live entries leaves fewer for auto", %{conn: conn} do
      {:ok, view, _} = host(conn)
      upload(view, "x.png") |> render_upload("x.png", 10)
      resume(view, [item("a.png"), item("b.png")])
      assert_reply(view, %{auto: ["id-a.png"], queued: ["id-b.png"]})
    end

    test "the policy decides, and gets the untrusted item", %{conn: conn} do
      policy = fn _socket, item, _free -> if item.context == "keep", do: :auto, else: :drop end
      Application.put_env(:phoenix_kit, :resumable_uploads_test_opts, policy: policy)
      on_exit(fn -> Application.delete_env(:phoenix_kit, :resumable_uploads_test_opts) end)
      {:ok, view, _} = host(conn)
      resume(view, [item("a.png", %{"context" => "keep"}), item("b.png", %{"context" => "x"})])
      assert_reply(view, %{auto: ["id-a.png"], drop: ["id-b.png"]})
    end

    test "hostile items are dropped: wrong types, huge strings, too many", %{conn: conn} do
      {:ok, view, _} = host(conn)

      resume(view, [
        "string",
        %{"key" => 5, "seq" => "1"},
        %{"key" => String.duplicate("k", 600), "seq" => "1"},
        item("ok.png")
      ])

      assert_reply(view, %{auto: ["id-ok.png"]})

      resume(view, for(i <- 1..40, do: item("n#{i}.png", %{"has_bytes" => false})))
      assert_reply(view, %{ask: ask})
      assert length(ask) <= 8, "at most max_entries * 4 items are looked at"
    end

    test "pending? is true from an automatic decision until the entry arrives", %{conn: conn} do
      {:ok, view, _} = host(conn)
      render_hook(view, "check", %{})
      refute has_element?(view, "#pending")

      resume(view, [item("a.png")])
      render_hook(view, "check", %{})
      assert has_element?(view, "#pending")

      render_upload(upload(view, "a.png"), "a.png")
      render_hook(view, "check", %{})
      refute has_element?(view, "#pending")
    end
  end

  describe "entries that vanish" do
    test "a cancelled file is reported as rejected, so the browser does not carry it on", %{
      conn: conn
    } do
      {:ok, view, _} = host(conn)
      k = key("a.png")
      render_upload(upload(view, "a.png"), "a.png", 10)
      [entry] = socket_entries(view)

      render_hook(view, "cancel", %{"ref" => entry.ref})
      assert_push_event(view, "pk-upload-rejected", %{upload: "photos", key: ^k})
      refute_push_event(view, "pk-upload-received", %{key: ^k}, 50)
    end

    test "a file that arrived (received) and was consumed is not reported as cancelled", %{
      conn: conn
    } do
      {:ok, view, _} = host(conn)
      k = key("a.png")
      render_upload(upload(view, "a.png"), "a.png")
      render_submit(element(view, "#f"))
      assert_push_event(view, "pk-upload-stored", %{key: ^k})
      refute_push_event(view, "pk-upload-rejected", %{key: ^k}, 50)
    end

    test "pending? ends when the carried-on file is cancelled or refused", %{conn: conn} do
      {:ok, view, _} = host(conn)
      resume(view, [item("a.png")])
      render_hook(view, "check", %{})
      assert has_element?(view, "#pending")

      big = String.duplicate("x", 40)
      assert {:error, _} = render_upload(upload(view, "big.png", :photos, big), "big.png")
      render_hook(view, "check", %{})
      refute has_element?(view, "#pending")
    end
  end

  describe "a failure of the moment" do
    test "a writer failure is neither acknowledged nor cancelled, and does not crash the host", %{
      conn: conn
    } do
      {:ok, view, _} = host(conn)
      k = key("a.png")

      input =
        file_input(view, "#f", :flaky, [
          %{name: "a.png", content: "12345", type: "image/png", last_modified: 7}
        ])

      render_upload(input, "a.png")

      assert Process.alive?(view.pid)
      refute_push_event(view, "pk-upload-rejected", %{key: ^k}, 100)

      # The entry is still there with its error, and the mechanism still answers.
      conf = :sys.get_state(view.pid).socket.assigns.uploads.flaky
      assert [%{client_name: "a.png"} = entry] = conf.entries

      assert {:writer_failure, :disk_full} in Phoenix.Component.upload_errors(conf, entry),
             "the fixture really is a failure of the moment"

      resume(view, [], "flaky")
      assert_reply(view, %{auto: [], queued: [], ask: [], drop: []})
    end
  end

  describe "slots across answers" do
    test "files decided auto earlier but not yet fed still take their slots", %{conn: conn} do
      {:ok, view, _} = host(conn)
      resume(view, [item("a.png"), item("b.png")])
      assert_reply(view, %{auto: ["id-a.png", "id-b.png"]})

      resume(view, [item("c.png")])
      assert_reply(view, %{auto: [], queued: ["id-c.png"]})
    end

    test "Resume feeds no more asked files than there are free slots", %{conn: conn} do
      {:ok, view, _} = host(conn)

      resume(view, for(n <- ~w(a b c), do: item("#{n}.png", %{"state" => "received"})))
      assert_reply(view, %{ask: ["id-a.png", "id-b.png", "id-c.png"]})

      row = "#pk-resumable-photos-#{:erlang.phash2("rec|order-1")}"
      view |> element(row <> "-resume") |> render_click()
      assert_push_event(view, "pk-upload-feed", %{ids: ["id-a.png", "id-b.png"]})
      assert has_element?(view, row <> "-ask"), "the third one still waits for a button"
    end
  end

  describe "hostile events" do
    test "an event of ours with no upload name never reaches the host", %{conn: conn} do
      {:ok, view, _} = host(conn)
      render_hook(view, "pk_upload_pick", %{})
      assert_reply(view, %{error: "not_attached"})
      assert Process.alive?(view.pid)
    end

    test "contexts beyond the limits are dropped loudly, not silently", %{conn: conn} do
      {:ok, view, _} = host(conn)

      # max_entries * 4 items per event, 20 seqs per key.
      for batch <- 0..2 do
        items =
          for i <- 1..8, do: %{"key" => key("a.png"), "seq" => "#{batch}-#{i}", "context" => "c"}

        render_hook(view, "pk_upload_pick", %{"upload" => "docs", "items" => items})
      end

      assert_reply(view, %{dropped: dropped})
      assert dropped > 0
    end
  end

  describe "the ask row" do
    test "Resume feeds the asked files and clears the row; Discard drops them", %{conn: conn} do
      {:ok, view, _} = host(conn)
      resume(view, [item("a.png", %{"state" => "received"})])
      row = "#pk-resumable-photos-#{:erlang.phash2("rec|order-1")}"
      assert has_element?(view, row <> "-ask")

      view |> element(row <> "-resume") |> render_click()
      assert_push_event(view, "pk-upload-feed", %{upload: "photos", ids: ["id-a.png"]})
      refute has_element?(view, row <> "-ask")

      resume(view, [item("b.png", %{"state" => "received"})])
      view |> element(row <> "-discard") |> render_click()
      assert_push_event(view, "pk-upload-drop", %{upload: "photos", ids: ["id-b.png"]})
      refute has_element?(view, row <> "-ask")
    end
  end

  describe "a page that dies and comes back" do
    test "the lost file arrives once and is saved once", %{conn: conn} do
      # The first page: the file is picked (the context reaches the server), then
      # the camera takes the browser away and the page is gone.
      Process.flag(:trap_exit, true)
      {:ok, first, _} = host(conn)

      render_hook(first, "pk_upload_pick", %{
        "upload" => "photos",
        "items" => [%{"key" => key("clip.png"), "seq" => "1", "context" => "folder-a"}]
      })

      GenServer.stop(first.pid, :shutdown)

      # The second page: the hook offers what it kept, the server says auto, the
      # hook feeds it through the form's upload.
      {:ok, second, _} = host(conn)
      resume(second, [item("clip.png", %{"id" => "r1"})])
      assert_reply(second, %{auto: ["r1"]})

      render_upload(upload(second, "clip.png"), "clip.png")
      render_submit(element(second, "#f"))
      assert_push_event(second, "pk-upload-stored", %{key: key})
      assert key == key("clip.png")

      assert render(second) |> Floki.parse_fragment!() |> Floki.find("p.saved") |> length() == 1

      # A second look after storing finds nothing left to carry on: the browser
      # deleted the record on `stored`.
      resume(second, [])
      assert_reply(second, %{auto: [], queued: [], ask: [], drop: []})
    end

    test "dying between received and stored loses no bytes: the record comes back as a button", %{
      conn: conn
    } do
      Process.flag(:trap_exit, true)
      {:ok, first, _} = host(conn)
      render_upload(upload(first, "clip.png"), "clip.png")
      GenServer.stop(first.pid, :shutdown)

      {:ok, second, _} = host(conn)
      resume(second, [item("clip.png", %{"id" => "r1", "state" => "received"})])
      assert_reply(second, %{auto: [], ask: ["r1"]})

      row = "#pk-resumable-photos-#{:erlang.phash2("rec|order-1")}"
      second |> element(row <> "-resume") |> render_click()
      assert_push_event(second, "pk-upload-feed", %{ids: ["r1"]})

      render_upload(upload(second, "clip.png"), "clip.png")
      render_submit(element(second, "#f"))
      assert render(second) =~ "clip.png@"
    end
  end

  defmodule BrowserHost do
    @moduledoc false
    use Phoenix.LiveView

    def mount(_params, _session, socket),
      do: {:ok, MediaBrowser.setup_uploads(socket)}

    # A host written before `resumable_uploads` existed: it passes nothing for it.
    def render(assigns) do
      ~H"""
      <.live_component
        module={MediaBrowser}
        id="media-browser"
        parent_uploads={@uploads}
      />
      """
    end
  end

  defmodule PlainBrowserHost do
    @moduledoc false
    use Phoenix.LiveView

    # A host with its own plain allow_upload and no setup_uploads/1.
    def mount(_params, _session, socket),
      do: {:ok, allow_upload(socket, :media_files, accept: :any, auto_upload: true)}

    def render(assigns) do
      ~H"""
      <.live_component module={MediaBrowser} id="media-browser" parent_uploads={@uploads} />
      """
    end
  end

  describe "a MediaBrowser host with its own allow_upload" do
    test "gets no hook (its events would have no handler) and does not crash", %{conn: conn} do
      {:ok, _} =
        Storage.create_bucket(%{
          name: "plain-#{System.unique_integer([:positive])}",
          provider: "local",
          endpoint: Path.join(System.tmp_dir!(), "pk_resumable_bucket"),
          enabled: true,
          priority: 0
        })

      {:ok, view, html} = live_isolated(conn, PlainBrowserHost)
      refute html =~ ~s(phx-hook="ResumableUpload")
      assert Process.alive?(view.pid)
    end
  end

  describe "a MediaBrowser host that does not pass resumable_uploads" do
    test "still gets the hook and automatic continuation; only the button row is missing", %{
      conn: conn
    } do
      {:ok, _} =
        Storage.create_bucket(%{
          name: "resumable-#{System.unique_integer([:positive])}",
          provider: "local",
          endpoint: Path.join(System.tmp_dir!(), "pk_resumable_bucket"),
          enabled: true,
          priority: 0
        })

      {:ok, view, html} = live_isolated(conn, BrowserHost)
      assert html =~ ~s(phx-hook="ResumableUpload")
      assert html =~ ~s(data-upload="media_files")

      render_hook(view, "pk_upload_resume", %{
        "upload" => "media_files",
        "items" => [item("clip.png")]
      })

      assert_reply(view, %{auto: ["id-clip.png"]})

      # A file that needs a decision is kept; no row, no crash.
      render_hook(view, "pk_upload_resume", %{
        "upload" => "media_files",
        "items" => [item("recv.png", %{"state" => "received"})]
      })

      assert_reply(view, %{ask: ["id-recv.png"]})
      refute has_element?(view, "[id$=-ask]")
      assert Process.alive?(view.pid)
    end
  end

  defp socket_entries(view) do
    :sys.get_state(view.pid).socket.assigns.uploads.photos.entries
  end
end
