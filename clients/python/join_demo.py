"""
Scans for an LDN network through ldnd, joins it, and reports what happens on it.

The ldnd counterpart of ``examples/join.py``, and the point of the whole exercise: no
``pycryptodome``, no ``python-netlink``, no ``wlan.py``, and no ``prod.keys``. The daemon owns all
of that. What is left here is a scan, a join, and an event loop.

    python join_demo.py --socket \\\\.\\pipe\\ldnd --password <hex> --seconds 20

**The password is a per-game constant, and it is not optional.** It goes into the CCMP link key, so
without the right one the host acknowledges every frame and then silently drops it; the join fails
in a way that looks exactly like a host ignoring you. It is not a secret; it is baked into the
title. ``frlg-ldn-trade`` keeps its own in ``frlgsim/transport.py``.
"""

import argparse
import sys

import trio

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

from ldnd import client as ldnd


def parse_hex(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise SystemExit("--password must be hex, for example fcb6f6ad...")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=r"\\.\pipe\ldnd")
    parser.add_argument("--password", default="", help="the game's passphrase, in hex")
    parser.add_argument("--name", default="ldnrs", help="the nickname other players see")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--comm-id", default=None, help="only join this title id, in hex")
    args = parser.parse_args()

    password = parse_hex(args.password) if args.password else b""
    wanted = int(args.comm_id, 16) if args.comm_id else None

    async with ldnd.connect(args.socket, name="join_demo") as connection:
        hello = connection.hello
        print("connected to ldnd %s" % (hello.daemon_version if hello else "?"))

        if not await connection.wait_for_radio(90_000):
            print("the adapter never became ready; is ldnd running with --usb?")
            return

        print("\nscanning...")
        networks = await connection.scan(dwell_ms=2500)
        print("found %i network(s)" % len(networks))

        for network in networks:
            print("  %r" % network)

        while connection.pending_event() is not None:
            pass

        candidates = [n for n in networks if n.is_joinable()]
        if wanted is not None:
            candidates = [n for n in candidates if n.local_communication_id == wanted]

        if not candidates:
            print("\nnothing joinable found")
            return

        network = candidates[0]
        print(
            "\njoining %016x on channel %i with a %i byte password..."
            % (network.local_communication_id, network.channel, len(password))
        )

        try:
            joined = await connection.connect(
                network,
                password=password,
                name=args.name.encode(),
            )
        except ldnd.DaemonError as err:
            print("\nFAIL  %s" % err)
            return

        async with joined:
            print(
                "\nPASS  joined as participant %i at %s"
                % (joined.participant_index, joined.local_address())
            )
            print("      broadcast %s" % joined.broadcast_address())

            info = joined.info()
            if info is not None:
                print("\nparticipants:")
                for index, participant in enumerate(info.participants):
                    if participant.connected:
                        print(
                            "  %i: %s %s %r"
                            % (
                                index,
                                participant.mac_address,
                                participant.ip_address,
                                participant.name_str(),
                            )
                        )

            refreshed = await joined.refresh()
            if refreshed is not None:
                print(
                    "\nre-read from the daemon: %i/%i participant(s)"
                    % (refreshed.num_participants, refreshed.max_participants)
                )

            channel = await connection.open_raw(joined)
            print("\nopened raw channel %i" % channel.handle)

            frames = 0
            print("\nwatching for %is..." % args.seconds)
            with trio.move_on_after(args.seconds):
                while True:
                    event = await connection.next_event()
                    if event is None:
                        break

                    if isinstance(event, ldnd.DataFrame):
                        frames += 1
                        if frames <= 3:
                            print("  %r from %s" % (event, _source_of(event.payload)))
                        continue

                    print("  %r" % event)

                    if isinstance(event, ldnd.Disconnected):
                        print("\nthe network ended")
                        return

            print("\n%i frame(s) received on the channel" % frames)
            await channel.close()

            print("\nPASS  still joined after %is" % args.seconds)


def _source_of(frame: bytes) -> str:
    if len(frame) < 12:
        return "?"

    return ":".join("%02x" % b for b in frame[6:12])


if __name__ == "__main__":
    trio.run(main)
