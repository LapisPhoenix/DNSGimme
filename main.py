import os
import re
import pathlib
import pyshark
from threading import Thread
from pyshark.packet.packet import Packet


class DNSGimme:
    def __init__(self, ignore: list[str] = None):
        """
        Monitors all DNS requests and logs them to a file, each log is 100mb. \n\nLogs are stored in ./output/
        :param ignore: a list of website urls to ignore DNS requests from or to.
        """
        self.packets = 0
        self.ignore = ignore if ignore else []
        self._check_integrity()

    def _process_packet(self, packet: Packet) -> None:
        if not hasattr(packet, "dns") or not hasattr(packet, "udp"):
            return

        checks = (
            hasattr(packet.dns, "qry_name"),
            packet.dns.qry_name not in self.ignore
        )

        if not all(checks):
            return

        self.packets += 1

        udp_layer = packet.udp
        time = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        site = packet.dns.qry_name

        src = packet.ipv6.src
        src_port = udp_layer.srcport
        dest = packet.ipv6.dst
        dest_port = udp_layer.dstport

        self._write_to_file(f"{time} - {site}  {src}:{src_port}  ->  {dest}:{dest_port}")

    def _write_to_file(self, string: str) -> None:
        log = self._find_latest_log()

        with open(log, "a") as f:
            f.write(string + "\n")

    @staticmethod
    def _check_integrity() -> None:
        cwd = pathlib.Path(os.getcwd())
        output = cwd / "output"

        if not output.exists():
            output.mkdir()
        elif output.is_file():
            raise Exception(f"{output} should be a directory, not a file!")

    def _find_latest_log(self) -> pathlib.Path:
        cwd = pathlib.Path(os.getcwd())
        output = cwd / "output"

        # Regex pattern to match filenames like dnsgimme-logs-<number>.txt
        pattern = r"dnsgimme-logs-(\d+)\.txt"
        pattern = re.compile(pattern)

        files = output.glob('*')
        latest = None
        latest_number = -1

        for file in files:
            match = pattern.match(file.name)
            if match:
                # Get the log number from the matched filename
                log_number = int(match.group(1))
                if log_number > latest_number:
                    latest_number = log_number
                    latest = file

        if latest is None:
            return output / "dnsgimme-logs-0.txt"

        if (latest.stat().st_size / 1000000) >= 100:
            return output / f"dnsgimme-logs-{latest_number + 1}.txt"

        return latest

    def sniff(self, interface: str, block: bool = True) -> None:
        """
        Sniff your network and log DNS.
        :param interface:
        :param block:
        :return:
        """
        if block:
            self._sniff(interface)
        else:
            thread = Thread(target=self._sniff, args=(interface, ))
            thread.start()

    def _sniff(self, interface: str) -> None:
        capture = pyshark.LiveCapture(interface)
        capture.apply_on_packets(self._process_packet)


def main():
    print(""":::::::::  ::::    :::  ::::::::        :::::::: ::::::::::: ::::    ::::  ::::    ::::  :::::::::: 
:+:    :+: :+:+:   :+: :+:    :+:      :+:    :+:    :+:     +:+:+: :+:+:+ +:+:+: :+:+:+ :+:        
+:+    +:+ :+:+:+  +:+ +:+             +:+           +:+     +:+ +:+:+ +:+ +:+ +:+:+ +:+ +:+        
+#+    +:+ +#+ +:+ +#+ +#++:++#++      :#:           +#+     +#+  +:+  +#+ +#+  +:+  +#+ +#++:++#   
+#+    +#+ +#+  +#+#+#        +#+      +#+   +#+#    +#+     +#+       +#+ +#+       +#+ +#+        
#+#    #+# #+#   #+#+# #+#    #+#      #+#    #+#    #+#     #+#       #+# #+#       #+# #+#        
#########  ###    ####  ########        ######## ########### ###       ### ###       ### ##########""")
    print("Tool by Lapis Pheonix")
    dnsg = DNSGimme()
    dnsg.sniff()
    print(f"\nSaved {dnsg.packets} packets.\n  - Made by Lapis Pheonix")


if __name__ == "__main__":
    main()
