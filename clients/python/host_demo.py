"""
Hosts an LDN network through ldnd and reports who joins it.

The mirror of ``join_demo.py``, and the Stage D acceptance check. Same absences as the join demo:
no ``pycryptodome``, no ``python-netlink``, no ``wlan.py``, no ``prod.keys``. What is left here is
a create, a channel, and an event loop.

    python host_demo.py --socket \\\\.\\pipe\\ldnd --comm-id 0100000001004000 --password <hex>

**The password is the same per-game constant a join needs, and it matters for the same reason.**
It goes into the CCMP key alongside the server random, so a host and a station that disagree about
it associate, complete the handshake, and then exchange nothing at all. That failure looks like a
dead link rather than a wrong key, which is why it is worth getting right before blaming the radio.

**Hosting needs two interfaces on one phy.** The AP carries the network and its control port; a
monitor carries the advertisement, because an advertisement is a broadcast action frame from a
network nobody has joined yet. A phy whose interface combinations do not allow AP plus monitor
cannot host, and that is reported as the create failing rather than as a network nobody can find.

To watch it work, run this, then run ``join_demo.py`` against a second adapter -- or put a Switch
in the same game's local-play lobby and look for the network in its list.
"""

import argparse
import sys

import trio

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

from ldnd import client as ldnd
from ldnd import protocol


def parse_hex(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise SystemExit("expected hex, for example fcb6f6ad...")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=r"\\.\pipe\ldnd")
    parser.add_argument(
        "--comm-id",
        default="0100000001004000",
        help="the title id stations filter their scan on, in hex",
    )
    parser.add_argument("--scene-id", type=int, default=0)
    parser.add_argument("--password", default="", help="the game's passphrase, in hex")
    parser.add_argument("--name", default="ldnrs", help="the nickname stations see")
    parser.add_argument("--channel", type=int, default=None, help="1, 6 or 11")
    parser.add_argument("--max", type=int, default=8, dest="max_participants")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument(
        "--lock-after",
        type=int,
        default=None,
        metavar="N",
        help="close the network to new stations once N have joined",
    )
    args = parser.parse_args()

    password = parse_hex(args.password) if args.password else b""
    comm_id = int(args.comm_id, 16)

    async with ldnd.connect(args.socket, name="host_demo") as connection:
        hello = connection.hello
        print("connected to ldnd %s" % (hello.daemon_version if hello else "?"))

        if hello is not None and not hello.capabilities & protocol.CAP_ACCESS_POINT:
            print("this daemon does not advertise ACCESS_POINT; it cannot host")
            return

        if not await connection.wait_for_radio(90_000):
            print("the adapter never became ready; is ldnd running with --usb?")
            return

        print(
            "\nhosting %016x scene %i on %s with a %i byte password..."
            % (
                comm_id,
                args.scene_id,
                "channel %i" % args.channel if args.channel else "a channel of its choosing",
                len(password),
            )
        )

        try:
            network = await connection.create_network(
                comm_id,
                scene_id=args.scene_id,
                password=password,
                name=args.name.encode(),
                channel=args.channel,
                max_participants=args.max_participants,
            )
        except ldnd.DaemonError as err:
            print("\nFAIL  %s" % err)
            return

        async with network:
            info = network.info()
            print("\nPASS  network is up at %s" % network.local_address())

            if info is not None:
                print("      ssid %s" % info.ssid.hex())
                print("      channel %i, up to %i participants" % (info.channel, info.max_participants))

            channel = await connection.open_raw(network)
            print("\nopened raw channel %i" % channel.handle)

            await connection.set_application_data(network, b"ldnrs host_demo")
            print("set application data; scanners will see it on the next advertisement")

            joined = 0
            locked = False
            frames = 0

            print("\nhosting for %is; waiting for stations..." % args.seconds)
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

                    if isinstance(event, ldnd.Joined):
                        joined += 1

                        if (
                            args.lock_after is not None
                            and not locked
                            and joined >= args.lock_after
                        ):
                            await connection.set_accept_policy(network, protocol.ACCEPT_NONE)
                            locked = True
                            print("  lobby locked after %i join(s)" % joined)

                    if isinstance(event, ldnd.Disconnected):
                        print("\nthe network ended")
                        return

            refreshed = await network.refresh()
            if refreshed is not None:
                print("\nparticipants:")
                for index, participant in enumerate(refreshed.participants):
                    if participant.connected:
                        print(
                            "  %i: %s %s %r%s"
                            % (
                                index,
                                participant.mac_address,
                                participant.ip_address,
                                participant.name_str(),
                                " (this host)" if index == 0 else "",
                            )
                        )

            print("\n%i frame(s) received on the channel" % frames)
            await channel.close()

            print("\nPASS  hosted for %is; %i station(s) joined" % (args.seconds, joined))


def _source_of(frame: bytes) -> str:
    if len(frame) < 12:
        return "?"

    return ":".join("%02x" % b for b in frame[6:12])


if __name__ == "__main__":
    trio.run(main)
