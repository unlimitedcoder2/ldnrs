"""
The ldnd counterpart of ``LDN/examples/scan.py``.

Same output, different plumbing: there is no ``keys`` argument and no crypto in this process --
the daemon owns ``prod.keys`` and hands back decoded networks.

Against a real adapter::

    cargo run -p ldnd -- --socket \\\\.\\pipe\\ldnd --usb 2357:0138 --keys prod.keys
    python clients/python/scan_demo.py \\\\.\\pipe\\ldnd

Against synthetic networks, with no hardware::

    cargo run -p ldn --example fake_scan_daemon -- \\\\.\\pipe\\ldn-fake
    python clients/python/scan_demo.py \\\\.\\pipe\\ldn-fake
"""

from __future__ import annotations

import os
import sys

import trio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ldnd  # noqa: E402

BAND_NAMES = {2: "2.4 GHz", 5: "5 GHz"}


def describe(index: int, network: ldnd.NetworkInfo) -> None:
    print()
    print("Network %i:" % index)
    print("\tLocal communication id: %016x" % network.local_communication_id)
    print("\tScene id: %i" % network.scene_id)
    print()
    print(
        "\tStation accept policy: %s"
        % ldnd.protocol.ACCEPT_POLICY_NAMES.get(network.accept_policy, network.accept_policy)
    )
    print("\tMaximum number of participants: %i" % network.max_participants)
    print(
        "\tApplication data: %s (%i bytes)"
        % (network.application_data.hex(), len(network.application_data))
    )
    print()
    print("\tHost address: %s" % network.address)
    print("\tWLAN band: %s" % BAND_NAMES.get(network.band, network.band))
    print("\tWLAN channel: %i" % network.channel)
    print("\tSSID: %s" % network.ssid.hex())
    print()
    print("\tLDN version: %i" % network.version)
    print("\tLDN protocol: %i" % network.protocol)
    print("\tSecurity mode: %i" % network.security_mode)
    print("\tJoinable: %s" % network.is_joinable())
    print()
    print("\tParticipants:")
    for participant in network.connected_participants():
        print("\t\tName: %s" % participant.name_str())
        print("\t\tIP address: %s" % participant.ip_address)
        print("\t\tMAC address: %s" % participant.mac_address)
        print("\t\tApplication version: %i" % participant.app_version)
        print(
            "\t\tPlatform: %s"
            % ldnd.protocol.PLATFORM_NAMES.get(participant.platform, participant.platform)
        )
        print("\t\t---")


async def main(path: str) -> int:
    async with ldnd.connect(path) as conn:
        print("Connected to ldnd %s" % conn.hello.daemon_version)
        print("Capabilities: %s" % ldnd.capability_names(conn.hello.capabilities))
        print("Radio ready: %s" % conn.hello.radio_ready)

        if not conn.hello.capabilities & ldnd.CAP_SCAN:
            print("This daemon cannot scan.")
            return 1

        if not await conn.wait_for_radio(90_000):
            print("The adapter never became ready; is ldnd running with --usb?")
            return 1

        print()
        print("Scanning...")

        try:
            networks = await conn.scan()
        except ldnd.DaemonError as err:
            print("Scan failed: %s" % err)
            if err.code == ldnd.STATUS_NO_KEYS:
                print("Start the daemon with --keys pointing at prod.keys.")
            elif err.code == ldnd.STATUS_NO_RADIO:
                print("No monitor interface is available; is an adapter attached?")
            return 1

        print("Found %i network(s)" % len(networks))
        for index, network in enumerate(networks):
            describe(index, network)

        return 0


if __name__ == "__main__":
    socket = sys.argv[1] if len(sys.argv) > 1 else r"\\.\pipe\ldnd"
    sys.exit(trio.run(main, socket))
