import unittest

from hids.parser import parse_netstat_output, split_address


SAMPLE_OUTPUT = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.10:49875     185.234.217.12:4444    ESTABLISHED     1234
  TCP    127.0.0.1:5040         127.0.0.1:5041         ESTABLISHED     999
  UDP    0.0.0.0:1900           *:*                                    5152
"""


class AttackDetectorTests(unittest.TestCase):
    def test_split_address_handles_ipv4_and_ipv6(self) -> None:
        self.assertEqual(split_address("192.168.1.10:443"), ("192.168.1.10", 443))
        self.assertEqual(split_address("[fe80::1]:5357"), ("fe80::1", 5357))
        self.assertEqual(split_address("*:*"), ("*", None))

    def test_parse_netstat_output_extracts_tcp_and_udp_records(self) -> None:
        records = parse_netstat_output(SAMPLE_OUTPUT)

        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].protocol, "TCP")
        self.assertEqual(records[-1].protocol, "UDP")
        self.assertEqual(records[-1].state, "STATELESS")


if __name__ == "__main__":
    unittest.main()
