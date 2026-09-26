"""
A tkinter front end for ``scan_demo.py``.

Against a real adapter::

    cargo run -p ldnd -- --socket \\\\.\\pipe\\ldnd --usb 2357:0138 --keys prod.keys
    python clients/python/scan_gui.py \\\\.\\pipe\\ldnd

Against synthetic networks, with no hardware::

    cargo run -p ldn --example fake_scan_daemon -- \\\\.\\pipe\\ldn-fake
    python clients/python/scan_gui.py \\\\.\\pipe\\ldn-fake

Against an ESP32 running the GB-Link bridge firmware, which serves ldnd itself over USB with its
own radio (needs pyserial; the Ports button lists the boards it can see)::

    python clients/python/scan_gui.py serial:COM8

Such a board keeps the LDN keys itself rather than taking them from ldnd's ``--keys``. For now,
connecting to one first stores the four it needs from ``DEFAULT_KEYS_FILE`` if it lacks any; Load
keys stores them again, from that file or one picked. Disconnecting hands the board back to its
standalone bridge.

Tk and trio each want to own the thread they run on, so they get one each: trio drives the pipe on
a worker thread and posts plain data onto a queue, and Tk drains that queue from its own event loop
with ``after``. Nothing in the worker touches a widget, and nothing in the GUI awaits.
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import time
import tkinter as tk

from tkinter import filedialog
from tkinter import font as tkfont
from tkinter import ttk

import trio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ldnd  # noqa: E402

DEFAULT_PIPE = r"\\.\pipe\ldnd"
BAND_NAMES = {2: "2.4 GHz", 5: "5 GHz"}
MAX_LOG_LINES = 2000

# What the GB-Link bridge firmware calls itself in Hello's daemon_version.
BOARD_PREFIX = "frlg-ldn-bridge"
BOARD_CHANNELS = range(1, 12)
# The USB-to-serial bridges ESP32 boards come with, and the ESP32's own USB.
BOARD_USB_VIDS = {0x303A: "Espressif", 0x10C4: "CP210x", 0x1A86: "CH34x", 0x0403: "FTDI"}
# The four prod.keys entries the board stores; it never sends them back.
BOARD_KEYS = (
    "aes_kek_generation_source",
    "aes_key_generation_source",
    "master_key_00",
    "master_key_12",
)
KEYS_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
# For now Load keys takes this file without asking; the dialog is only for when it is missing.
DEFAULT_KEYS_FILE = r"C:\Users\archbtw\frlg\ldnrs\prod.keys"


def describe_error(err: BaseException) -> str:
    while isinstance(err, BaseExceptionGroup) and err.exceptions:
        err = err.exceptions[0]

    if isinstance(err, ldnd.DaemonError):
        return str(err)

    return "%s: %s" % (type(err).__name__, err)


def scan_hint(code: int, board: bool) -> str:
    if code == ldnd.STATUS_NO_KEYS:
        if board:
            return "The board has no keys yet: disconnect, then use Load keys with your prod.keys."
        return "Start the daemon with --keys pointing at prod.keys."
    if code == ldnd.STATUS_NO_RADIO:
        return "No monitor interface is available; is an adapter attached?"
    if code == ldnd.STATUS_BUSY:
        if board:
            return "The board's radio is busy; disconnect and connect again."
        return "Another scan is already running on this daemon."
    return ""


def find_boards() -> list[tuple[str, str]] | None:
    """``(path, description)`` for each serial port that looks like an ESP32; None without pyserial."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return None

    boards = []
    for port in sorted(list_ports.comports(), key=lambda port: port.device):
        if port.vid in BOARD_USB_VIDS:
            boards.append(
                (
                    ldnd.client.SERIAL_PREFIX + port.device,
                    "%s (%s %04x:%04x)" % (port.description, BOARD_USB_VIDS[port.vid], port.vid, port.pid),
                )
            )

    return boards


def read_board_keys(path: str) -> dict[str, str]:
    """The four entries of a prod.keys the board needs, or ValueError naming what is missing."""
    found = {}
    with open(path, encoding="utf-8", errors="replace") as keys:
        for line in keys:
            name, equals, value = line.partition("=")
            name, value = name.strip().lower(), value.strip().lower()
            if equals and name in BOARD_KEYS and re.fullmatch(r"[0-9a-f]{32}", value):
                found[name] = value

    missing = [name for name in BOARD_KEYS if name not in found]
    if missing:
        raise ValueError("%s has no usable %s." % (os.path.basename(path), ", ".join(missing)))

    return found


def keys_complete(status: str) -> bool:
    """Whether an ``LDN_KEYS kek=1 gen=1 ...`` line says every key is on the board."""
    flags = dict(part.split("=", 1) for part in status.split()[1:] if "=" in part)
    return bool(flags) and all(value == "1" for value in flags.values())


def _read_console(port, done, seconds: float) -> list[str]:
    """The board's console lines until ``done(line)`` is true or the time is up."""
    lines, pending = [], b""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pending += port.read(4096)
        *complete, pending = pending.split(b"\n")
        for raw in complete:
            line = raw.decode("ascii", "replace").strip()
            lines.append(line)
            if done(line):
                return lines

    return lines


def _send_board_keys(port_name: str, keys: dict[str, str], only_if_missing: bool) -> tuple[bool, list[str]]:
    """
    Types the keys into the board's text console. Returns whether they were sent, and the
    board's answers; with ``only_if_missing`` a board that has them all is left alone.
    """
    import serial

    if "://" in port_name:
        port = serial.serial_for_url(port_name, timeout=0.1)
    else:
        port = serial.Serial()
        port.port, port.baudrate, port.timeout = port_name, ldnd.client.SerialConnection.BAUD, 0.1
        port.dtr, port.rts = True, False   # as SerialConnection opens it: without resetting the chip
        port.open()
        port.dtr = False

    try:
        if only_if_missing:
            port.write(b"\nLDN_KEYS\n")
            status = [
                line
                for line in _read_console(port, lambda line: line.startswith("LDN_KEYS "), 3)
                if line.startswith("LDN_KEYS ")
            ]
            if status and keys_complete(status[-1]):
                return False, status

        # A board with no keys stops its bridge the first time it finds a room; restart it.
        commands = ["LDN_KEY %s %s" % (name, keys[name]) for name in BOARD_KEYS]
        port.write(("\n" + "\n".join(commands + ["LDN_KEYS", "LDN_BRIDGE_START"]) + "\n").encode())
        lines = _read_console(port, lambda line: line == "LDN_BRIDGE_STARTED", 5)
        return True, [line for line in lines if line.startswith(("LDN_KEY_OK", "LDN_KEY_BAD", "LDN_KEYS "))]
    finally:
        port.close()


async def load_board_keys(
    path: str, keys: dict[str, str], only_if_missing: bool = False
) -> tuple[bool, list[str]]:
    # Only the text console takes LDN_KEY. Shutdown gets it there from wherever the board is, and
    # leaves the port without the line that would take the console back for the daemon.
    async with ldnd.connect(path, name="ldn-scan-gui", version="1.0.0") as conn:
        if not conn.hello.daemon_version.startswith(BOARD_PREFIX):
            raise ValueError("%s is %s, not a GB-Link bridge board." % (path, conn.hello.daemon_version))
        await conn.shutdown()

    return await trio.to_thread.run_sync(
        _send_board_keys, ldnd.client.serial_port_name(path), keys, only_if_missing
    )


class Worker:
    def __init__(self, outbox: "queue.Queue[tuple[str, object]]"):
        self._outbox = outbox
        self._token: trio.lowlevel.TrioToken | None = None
        self._commands: trio.MemorySendChannel | None = None
        self._scanning = False
        self._board = False

        # Radio readiness as a condition variable: the state, plus an event that is set and
        # replaced on every change. Clearing a trio.Event is not a thing, and swapping in a fresh
        # one while a scan waits on the old one would leave that scan waiting on an object nobody
        # will ever set -- so waiters re-read the state after each wake instead.
        self._radio_state = ldnd.RADIO_IDLE
        self._radio_changed: trio.Event | None = None


    def start(self, path: str) -> None:
        threading.Thread(
            target=trio.run,
            args=(self._main, path),
            name="ldnd-client",
            daemon=True,
        ).start()

    def post(self, command: str, *args) -> bool:
        token, commands = self._token, self._commands
        if token is None or commands is None:
            return False

        try:
            trio.from_thread.run_sync(commands.send_nowait, (command, args), trio_token=token)
            return True
        except (
            trio.RunFinishedError,
            trio.WouldBlock,
            trio.BrokenResourceError,
            trio.ClosedResourceError,
            RuntimeError,
        ):
            return False


    def _emit(self, kind: str, payload: object = None) -> None:
        self._outbox.put((kind, payload))

    async def _main(self, path: str) -> None:
        self._token = trio.lowlevel.current_trio_token()
        self._radio_changed = trio.Event()
        send, recv = trio.open_memory_channel(64)
        self._commands = send

        try:
            await self._ensure_keys(path)

            async with ldnd.connect(
                path,
                name="ldn-scan-gui",
                version="1.0.0",
                busy_retry_ms=2000,
            ) as conn:
                self._radio_state = (
                    ldnd.RADIO_READY if conn.hello.radio_ready else ldnd.RADIO_IDLE
                )
                self._board = conn.hello.daemon_version.startswith(BOARD_PREFIX)
                self._emit("hello", conn.hello)

                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self._pump_events, conn)
                    await self._command_loop(conn, nursery, recv)
                    nursery.cancel_scope.cancel()
        except OSError as err:
            if ldnd.client.is_serial_path(path):
                self._emit(
                    "error",
                    "Could not open %s: %s. Is the board plugged in, and running bridge firmware "
                    "with ldnd?" % (path, err),
                )
            else:
                self._emit("error", "Could not open %s: %s. Is ldnd running?" % (path, err))
        except BaseException as err:  # noqa: BLE001 - the GUI is the only place left to report it
            self._emit("error", describe_error(err))
        finally:
            self._token = None
            self._commands = None
            self._emit("closed")

    async def _ensure_keys(self, path: str) -> None:
        """For now a board is given DEFAULT_KEYS_FILE's keys on connecting, if it lacks any."""
        if not ldnd.client.is_serial_path(path) or not os.path.isfile(DEFAULT_KEYS_FILE):
            return

        try:
            keys = read_board_keys(DEFAULT_KEYS_FILE)
        except (OSError, ValueError) as err:
            self._emit("note", "Not loading keys from %s: %s" % (DEFAULT_KEYS_FILE, err))
            return

        try:
            stored, replies = await load_board_keys(path, keys, only_if_missing=True)
        except ValueError as err:   # not a bridge board: nothing to give it
            self._emit("note", str(err))
            return

        self._emit("keys", (path, stored, replies))

    async def _command_loop(self, conn, nursery, recv) -> None:
        async for command, args in recv:
            try:
                if command == "scan":
                    if not self._scanning:
                        self._scanning = True
                        nursery.start_soon(self._scan, conn, *args)
                elif command == "cancel":
                    if self._scanning:
                        await conn.scan_cancel()
                elif command == "log":
                    await conn.subscribe_log()
                    self._emit("note", "Subscribed to the daemon log.")
                elif command == "disconnect":
                    if self._board:
                        # A board's own job is the standalone bridge, which Shutdown restarts.
                        # ldnd proper has no such thing and is left running.
                        await conn.shutdown()
                        self._emit("note", "Handed the board back to its standalone bridge.")
                    return
            except ldnd.DaemonError as err:
                self._emit("note", "%s" % err)

    async def _scan(self, conn, channels, dwell_ms, timeout_ms) -> None:
        try:
            if not await self._wait_for_radio():
                return

            self._emit("scan_started")
            networks = await conn.scan(
                channels=channels,
                dwell_ms=dwell_ms,
                timeout_ms=timeout_ms,
            )
            self._emit("scan_done", networks)
        except ldnd.DaemonError as err:
            self._emit("scan_failed", "%s. %s" % (err, scan_hint(err.code, self._board)))
        except trio.Cancelled:
            raise
        except BaseException as err:  # noqa: BLE001
            self._emit("scan_failed", describe_error(err))
        finally:
            self._scanning = False

    async def _wait_for_radio(self, timeout_s: float = 90.0) -> bool:
        if self._radio_state == ldnd.RADIO_READY:
            return True

        self._emit("note", "Waiting for the adapter to come up...")

        with trio.move_on_after(timeout_s):
            while self._radio_state != ldnd.RADIO_READY:
                if self._radio_state == ldnd.RADIO_FAILED:
                    self._emit("scan_failed", "The adapter failed to come up.")
                    return False

                changed = self._radio_changed
                await changed.wait()

            return True

        self._emit(
            "scan_failed",
            "The adapter never became ready; is ldnd running with --usb?",
        )
        return False

    async def _pump_events(self, conn) -> None:
        async for event in conn.events():
            if isinstance(event, ldnd.RadioStateChanged):
                self._radio_state = event.state
                changed, self._radio_changed = self._radio_changed, trio.Event()
                changed.set()
                self._emit("radio", event)
            elif isinstance(event, ldnd.NetworkFound):
                self._emit("found", event.network)
            elif isinstance(event, ldnd.ScanDone):
                self._emit("note", "Scan finished: %i network(s)." % event.count)
            elif isinstance(event, ldnd.LogLine):
                self._emit("log", event.line.rstrip())
            elif isinstance(event, ldnd.LogDropped):
                self._emit("log", "[%i log lines dropped]" % event.lines)


class ScanGui:
    COLUMNS = (
        ("index", "#", 34, tk.E),
        ("comm_id", "Communication id", 140, tk.W),
        ("scene", "Scene", 50, tk.E),
        ("band", "Band", 62, tk.W),
        ("channel", "Ch", 34, tk.E),
        ("players", "Players", 58, tk.E),
        ("policy", "Policy", 84, tk.W),
        ("joinable", "Joinable", 62, tk.W),
        ("host", "Host address", 128, tk.W),
        ("ldn", "LDN", 60, tk.W),
    )

    def __init__(self, root: tk.Tk, pipe: str):
        self.root = root
        self.inbox: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self.worker: Worker | None = None
        self.networks: list[ldnd.NetworkInfo] = []
        self.connected = False
        self.scanning = False
        self.can_log = False
        self.failure: str | None = None
        self.board = False       # connected to a GB-Link bridge board rather than ldnd
        self.loading_keys = False
        self.closing = False
        self.destroyed = False

        root.title("LDN scan")
        root.geometry("980x640")
        root.minsize(720, 460)

        self.pipe_var = tk.StringVar(value=pipe)
        self.channels_var = tk.StringVar(value="1, 6, 11")
        self.dwell_var = tk.StringVar(value="110")
        self.timeout_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Not connected.")
        self.radio_var = tk.StringVar(value="Radio: -")

        self._build(root)
        self._set_controls()
        self._note("Ready. Start ldnd or plug in a bridge board, then press Connect.")
        self._on_ports()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(50, self._drain)


    def _build(self, root: tk.Tk) -> None:
        self.mono = tkfont.nametofont("TkFixedFont").copy()

        bar = ttk.Frame(root, padding=(8, 8, 8, 4))
        bar.pack(fill=tk.X)

        # ldnd's pipe, or a bridge board's serial port: the list offers the boards it can see.
        ttk.Label(bar, text="Daemon:").pack(side=tk.LEFT)
        self.pipe_entry = ttk.Combobox(bar, textvariable=self.pipe_var, width=24)
        self.pipe_entry.pack(side=tk.LEFT, padx=(4, 4))
        self.pipe_entry.bind("<<ComboboxSelected>>", lambda _event: self._set_controls())
        self.pipe_entry.bind("<KeyRelease>", lambda _event: self._set_controls())
        self.ports_button = ttk.Button(bar, text="Ports", width=6, command=self._on_ports)
        self.ports_button.pack(side=tk.LEFT, padx=(0, 4))
        self.connect_button = ttk.Button(bar, text="Connect", command=self._on_connect)
        self.connect_button.pack(side=tk.LEFT)
        self.keys_button = ttk.Button(bar, text="Load keys", command=self._on_load_keys)
        self.keys_button.pack(side=tk.LEFT, padx=(4, 0))

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        ttk.Label(bar, text="Channels:").pack(side=tk.LEFT)
        self.channels_entry = ttk.Entry(bar, textvariable=self.channels_var, width=11)
        self.channels_entry.pack(side=tk.LEFT, padx=(4, 8))

        ttk.Label(bar, text="Dwell ms:").pack(side=tk.LEFT)
        self.dwell_entry = ttk.Entry(bar, textvariable=self.dwell_var, width=6)
        self.dwell_entry.pack(side=tk.LEFT, padx=(4, 8))

        ttk.Label(bar, text="Timeout ms:").pack(side=tk.LEFT)
        self.timeout_entry = ttk.Entry(bar, textvariable=self.timeout_var, width=7)
        self.timeout_entry.pack(side=tk.LEFT, padx=(4, 8))

        self.scan_button = ttk.Button(bar, text="Scan", command=self._on_scan)
        self.scan_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(bar, text="Stop", command=self._on_stop)
        self.stop_button.pack(side=tk.LEFT, padx=(4, 0))
        self.log_button = ttk.Button(bar, text="Daemon log", command=self._on_subscribe_log)
        self.log_button.pack(side=tk.LEFT, padx=(4, 0))

        panes = ttk.PanedWindow(root, orient=tk.VERTICAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        table = ttk.Frame(panes)
        self.tree = ttk.Treeview(
            table,
            columns=[name for name, _, _, _ in self.COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for name, title, width, anchor in self.COLUMNS:
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, anchor=anchor, stretch=(name == "comm_id"))

        scroll = ttk.Scrollbar(table, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        panes.add(table, weight=3)

        book = ttk.Notebook(panes)
        self.details = self._text_tab(book, "Details")
        self.log = self._text_tab(book, "Log")
        panes.add(book, weight=2)

        status = ttk.Frame(root, padding=(8, 2, 8, 6))
        status.pack(fill=tk.X)
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT)
        ttk.Label(status, textvariable=self.radio_var).pack(side=tk.RIGHT)

    def _text_tab(self, book: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(book)
        text = tk.Text(frame, wrap=tk.NONE, font=self.mono, height=10, state=tk.DISABLED)

        vertical = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text.grid(row=0, column=0, sticky=tk.NSEW)
        vertical.grid(row=0, column=1, sticky=tk.NS)
        horizontal.grid(row=1, column=0, sticky=tk.EW)

        book.add(frame, text=title)
        return text


    def _set_controls(self) -> None:
        idle = not self.scanning
        free = not self.connected and not self.loading_keys
        self.connect_button.configure(text="Disconnect" if self.connected else "Connect")
        self.connect_button.configure(state=tk.DISABLED if self.loading_keys else tk.NORMAL)
        self.pipe_entry.configure(state=tk.NORMAL if free else tk.DISABLED)
        self.ports_button.configure(state=tk.NORMAL if free else tk.DISABLED)
        # Keys go in through the board's text console, which a connection holds.
        board_path = ldnd.client.is_serial_path(self.pipe_var.get().strip())
        self.keys_button.configure(state=tk.NORMAL if free and board_path else tk.DISABLED)
        self.scan_button.configure(
            state=tk.NORMAL if self.connected and idle else tk.DISABLED
        )
        self.stop_button.configure(
            state=tk.NORMAL if self.connected and self.scanning else tk.DISABLED
        )
        self.log_button.configure(
            state=tk.NORMAL if self.connected and self.can_log else tk.DISABLED
        )

    def _write(self, text: tk.Text, content: str, *, append: bool) -> None:
        text.configure(state=tk.NORMAL)
        if append:
            text.insert(tk.END, content + "\n")
            excess = int(text.index(tk.END).split(".")[0]) - MAX_LOG_LINES
            if excess > 0:
                text.delete("1.0", "%i.0" % excess)
            text.see(tk.END)
        else:
            text.delete("1.0", tk.END)
            text.insert("1.0", content)
        text.configure(state=tk.DISABLED)

    def _note(self, message: str) -> None:
        self.status_var.set(message)
        self._write(self.log, message, append=True)


    def _on_connect(self) -> None:
        if self.connected:
            if self.worker is not None:
                self.worker.post("disconnect")
            self._note("Disconnecting...")
            return

        path = self.pipe_var.get().strip()
        if not path:
            self._note(
                "Enter the daemon's pipe path, for example %s, or a board's port, for example "
                "serial:COM8" % DEFAULT_PIPE
            )
            return

        self.failure = None
        self.worker = Worker(self.inbox)
        self.worker.start(path)
        self._note("Connecting to %s ..." % path)

    def _on_scan(self) -> None:
        if self.worker is None or not self.connected:
            return

        try:
            channels = self._parse_channels()
            dwell_ms = self._parse_int(self.dwell_var.get(), "dwell")
            timeout_ms = self._parse_int(self.timeout_var.get(), "timeout")
        except ValueError as err:
            self._note(str(err))
            return

        if self.worker.post("scan", channels, dwell_ms, timeout_ms):
            self.scanning = True
            self._set_controls()

    def _on_stop(self) -> None:
        if self.worker is not None:
            self.worker.post("cancel")
            self._note("Asking the daemon to stop the scan...")

    def _on_subscribe_log(self) -> None:
        if self.worker is not None and self.worker.post("log"):
            self.can_log = False
            self._set_controls()

    def _parse_channels(self) -> list[int] | None:
        raw = self.channels_var.get().replace(",", " ").split()
        if not raw:
            return None

        channels = []
        for part in raw:
            try:
                channel = int(part, 10)
            except ValueError:
                raise ValueError("%r is not a channel number." % part) from None
            if not 1 <= channel <= 165:
                raise ValueError("Channel %i is out of range." % channel)
            if self.board and channel not in BOARD_CHANNELS:
                raise ValueError("The board's radio has 2.4 GHz channels 1 to 11, not %i." % channel)
            channels.append(channel)

        return channels

    @staticmethod
    def _parse_int(raw: str, what: str) -> int | None:
        raw = raw.strip()
        if not raw:
            return None
        try:
            value = int(raw, 10)
        except ValueError:
            raise ValueError("The %s must be a whole number of milliseconds." % what) from None
        if value <= 0:
            raise ValueError("The %s must be greater than zero." % what)
        return value

    def _on_close(self) -> None:
        # A board is handed back to its bridge as the connection closes, which takes a moment;
        # closing the window at once would end the process first. Wait for it, within reason.
        if self.worker is not None and self.board and self.worker.post("disconnect"):
            self.closing = True
            self.status_var.set("Handing the board back...")
            self.root.after(3000, self._destroy)
            return

        if self.worker is not None:
            self.worker.post("disconnect")
        self._destroy()

    def _on_ports(self) -> None:
        boards = find_boards()
        paths = [DEFAULT_PIPE]
        if boards is None:
            self._note("Bridge boards need pyserial (pip install pyserial); only pipes are offered.")
        else:
            for path, description in boards:
                paths.append(path)
                self._write(self.log, "Board port %s: %s" % (path, description), append=True)
            if not boards:
                self._write(self.log, "No ESP32 board is plugged in.", append=True)

        current = self.pipe_var.get().strip()
        if current and current not in paths:
            paths.append(current)
        self.pipe_entry.configure(values=paths)

    def _on_load_keys(self) -> None:
        path = self.pipe_var.get().strip()
        if self.connected or self.loading_keys or not ldnd.client.is_serial_path(path):
            return

        keys_file = DEFAULT_KEYS_FILE
        if not os.path.isfile(keys_file):
            keys_file = filedialog.askopenfilename(
                parent=self.root,
                title="prod.keys to store on the board",
                initialdir=KEYS_DIR,
                filetypes=[("Switch keys", "*.keys"), ("All files", "*.*")],
            )
            if not keys_file:
                return

        try:
            keys = read_board_keys(keys_file)
        except (OSError, ValueError) as err:
            self._note("Cannot use %s: %s" % (keys_file, err))
            return

        self.loading_keys = True
        self._set_controls()
        self._note("Storing the keys from %s on %s ..." % (os.path.basename(keys_file), path))
        threading.Thread(
            target=trio.run,
            args=(self._load_keys, path, keys),
            name="ldnd-board-keys",
            daemon=True,
        ).start()

    async def _load_keys(self, path: str, keys: dict[str, str]) -> None:
        # Runs on its own thread; like the worker, it only posts to the inbox.
        try:
            stored, replies = await load_board_keys(path, keys)
            self.inbox.put(("keys", (path, stored, replies)))
        except BaseException as err:  # noqa: BLE001 - reported in the GUI
            self.inbox.put(("keys_failed", "%s: %s" % (path, describe_error(err))))


    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.inbox.get_nowait()
                self._handle(kind, payload)
                if self.destroyed:
                    return
        except queue.Empty:
            pass

        self.root.after(50, self._drain)

    def _destroy(self) -> None:
        if not self.destroyed:
            self.destroyed = True
            self.root.destroy()

    def _handle(self, kind: str, payload) -> None:
        if kind == "hello":
            self.connected = True
            self.board = payload.daemon_version.startswith(BOARD_PREFIX)
            caps = ldnd.capability_names(payload.capabilities)
            self._note(
                "Connected to ldnd %s (%s)." % (payload.daemon_version, ", ".join(caps) or "no capabilities")
            )
            self.radio_var.set("Radio: %s" % ("READY" if payload.radio_ready else "waiting"))
            self.can_log = True
            if not payload.capabilities & ldnd.CAP_SCAN:
                self._note("This daemon cannot scan.")
            self._set_controls()

        elif kind == "closed":
            if self.closing:
                self._destroy()
                return
            self.connected = False
            self.scanning = False
            self.board = False
            self.worker = None
            self.can_log = False
            self.radio_var.set("Radio: -")
            self._write(self.log, "Disconnected.", append=True)
            self.status_var.set(
                "Disconnected: %s" % self.failure if self.failure else "Disconnected."
            )
            self._set_controls()

        elif kind == "keys":
            # From Load keys, or from connecting to a board that lacked some.
            path, sent, replies = payload
            self.loading_keys = False
            accepted = [line.split()[1] for line in replies if line.startswith("LDN_KEY_OK ")]
            status = [line for line in replies if line.startswith("LDN_KEYS ")]
            # if not sent:
            #     self._note("%s already has its keys. %s" % (path, status[-1] if status else ""))
            # elif set(accepted) == set(BOARD_KEYS):
            #     self._note("Stored the four keys on %s. %s" % (path, status[-1] if status else ""))
            # else:
            #     missing = [name for name in BOARD_KEYS if name not in accepted]
            #     self._note(
            #         "The board did not take %s: %s" % (", ".join(missing), "; ".join(replies) or "no answer")
            #     )
            self._set_controls()

        elif kind == "keys_failed":
            self.loading_keys = False
            self._note("Could not store the keys: %s" % payload)
            self._set_controls()

        elif kind == "error":
            self.failure = str(payload)
            self._note(str(payload))

        elif kind == "note":
            self._note(str(payload))

        elif kind == "radio":
            state = ldnd.radio_name(payload.state)
            self.radio_var.set("Radio: %s" % state)
            self._note("Radio: %s%s" % (state, ": %s" % payload.message if payload.message else ""))

        elif kind == "scan_started":
            self.networks = []
            self.tree.delete(*self.tree.get_children())
            self._write(self.details, "", append=False)
            self._note("Scanning...")

        elif kind == "found":
            self._add_network(payload)
            self.status_var.set("Scanning... %i network(s)" % len(self.networks))

        elif kind == "scan_done":
            self.scanning = False
            self.networks = []
            self.tree.delete(*self.tree.get_children())
            for network in payload:
                self._add_network(network)
            self._note("Found %i network(s)." % len(payload))
            self._set_controls()
            if self.networks:
                first = self.tree.get_children()[0]
                self.tree.selection_set(first)
                self.tree.focus(first)

        elif kind == "scan_failed":
            self.scanning = False
            self._note("Scan failed: %s" % payload)
            self._set_controls()

        elif kind == "log":
            self._write(self.log, str(payload), append=True)


    def _add_network(self, network: ldnd.NetworkInfo) -> None:
        index = len(self.networks)
        self.networks.append(network)

        self.tree.insert(
            "",
            tk.END,
            iid=str(index),
            values=(
                index,
                "%016x" % network.local_communication_id,
                network.scene_id,
                BAND_NAMES.get(network.band, network.band),
                network.channel,
                "%i/%i" % (network.num_participants, network.max_participants),
                ldnd.protocol.ACCEPT_POLICY_NAMES.get(
                    network.accept_policy, network.accept_policy
                ),
                "yes" if network.is_joinable() else "no",
                str(network.address),
                "v%i proto %i" % (network.version, network.protocol),
            ),
        )

    def _on_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return

        index = int(selection[0])
        if index < len(self.networks):
            self._write(self.details, self._describe(index, self.networks[index]), append=False)

    @staticmethod
    def _describe(index: int, network: ldnd.NetworkInfo) -> str:
        lines = [
            "Network %i:" % index,
            "\tLocal communication id: %016x" % network.local_communication_id,
            "\tScene id: %i" % network.scene_id,
            "",
            "\tStation accept policy: %s"
            % ldnd.protocol.ACCEPT_POLICY_NAMES.get(network.accept_policy, network.accept_policy),
            "\tMaximum number of participants: %i" % network.max_participants,
            "\tApplication data: %s (%i bytes)"
            % (network.application_data.hex(), len(network.application_data)),
            "",
            "\tHost address: %s" % network.address,
            "\tWLAN band: %s" % BAND_NAMES.get(network.band, network.band),
            "\tWLAN channel: %i" % network.channel,
            "\tSSID: %s" % network.ssid.hex(),
            "",
            "\tLDN version: %i" % network.version,
            "\tLDN protocol: %i" % network.protocol,
            "\tSecurity mode: %i" % network.security_mode,
            "\tJoinable: %s" % network.is_joinable(),
            "",
            "\tParticipants:",
        ]

        for participant in network.connected_participants():
            lines += [
                "\t\tName: %s" % participant.name_str(),
                "\t\tIP address: %s" % participant.ip_address,
                "\t\tMAC address: %s" % participant.mac_address,
                "\t\tApplication version: %i" % participant.app_version,
                "\t\tPlatform: %s"
                % ldnd.protocol.PLATFORM_NAMES.get(participant.platform, participant.platform),
                "\t\t---",
            ]

        return "\n".join(lines)


def main(pipe: str) -> int:
    root = tk.Tk()
    ScanGui(root, pipe)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PIPE))
