import contextlib
import datetime as dt
import io
import ipaddress
import json
import os
import socketserver
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scopeguard as sg  # noqa: E402

UTC = dt.timezone.utc
TOKEN = "sg_test-token-0123456789abcdef"
INSIDE = dt.datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

SCOPE = f'''
[engagement]
id = "ACME-2026-11"
client = "ACME Ltd."
token = "{TOKEN}"
not_before = 2026-11-20T09:00:00+03:00
not_after = 2026-11-27T18:00:00+03:00

[[target]]
domain = "example.com"
exclude = ["mail.example.com", "203.0.113.9"]

[[target]]
domain = "shop.example.com"
proof = "example.com"
resolves_within = ["203.0.113.0/28"]

[[target]]
cidr = "203.0.113.0/28"
proof = "example.com"
exclude = ["203.0.113.8/30"]
'''


def write_scope(directory, text=SCOPE):
    path = Path(directory) / "scope.toml"
    path.write_text(text, encoding="utf-8")
    return path


class GuardCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scope = sg.load_scope(write_scope(self.tmp.name))
        self.records = {"_scopeguard.example.com": [self.scope.record_value]}
        self.addresses = {"shop.example.com": ["203.0.113.4"]}
        self.now = INSIDE

    def guard(self):
        def resolve(host):
            return [ipaddress.ip_address(a) for a in self.addresses.get(host, ["198.51.100.7"])]
        return sg.Guard(self.scope, txt_lookup=lambda name: self.records.get(name, []),
                        resolve=resolve, now=lambda: self.now)

    def assertAllowed(self, target):
        verdict = self.guard().check(target)
        self.assertTrue(verdict.allowed, verdict.reason)
        return verdict

    def assertDenied(self, target, fragment):
        verdict = self.guard().check(target)
        self.assertFalse(verdict.allowed, f"{target} was allowed")
        self.assertIn(fragment, verdict.reason)
        return verdict


class ScopeMatching(GuardCase):
    def test_domain_and_subdomains_are_in_scope(self):
        self.assertAllowed("example.com")
        self.assertAllowed("app.example.com")
        self.assertAllowed("deep.api.example.com")

    def test_lookalike_domain_is_not_a_subdomain(self):
        self.assertDenied("evilexample.com", "not in the agreed scope")
        self.assertDenied("example.com.attacker.net", "not in the agreed scope")

    def test_excluded_host_and_its_subdomains(self):
        self.assertDenied("mail.example.com", "excluded")
        self.assertDenied("smtp.mail.example.com", "excluded")

    def test_urls_ports_and_case_are_normalised(self):
        self.assertEqual(self.assertAllowed("https://App.Example.com:8443/login?x=1").target, "app.example.com")
        self.assertAllowed("app.example.com:8443")
        self.assertAllowed("app.example.com.")

    def test_addresses_and_ranges(self):
        self.assertEqual(self.assertAllowed("203.0.113.5").target, "203.0.113.5")
        self.assertAllowed("203.0.113.0/30")
        self.assertDenied("203.0.113.200", "not inside any agreed range")
        self.assertDenied("203.0.112.0/20", "not inside any agreed range")

    def test_excluded_addresses(self):
        self.assertDenied("203.0.113.9", "excluded")
        self.assertDenied("203.0.113.0/28", "excluded")  # the range contains excluded addresses

    def test_an_address_is_not_covered_by_a_domain_target(self):
        self.assertDenied("198.51.100.7", "not inside any agreed range")

    def test_garbage_is_denied(self):
        self.assertDenied("http://", "cannot read a host")
        self.assertDenied("exa mple.com", "not a valid host name")

    def test_host_resolving_to_an_excluded_address(self):
        self.addresses["old.example.com"] = ["203.0.113.9"]
        self.assertDenied("old.example.com", "excluded")


class ThirdPartyHosting(GuardCase):
    def test_host_inside_the_agreed_ranges(self):
        self.assertAllowed("shop.example.com")

    def test_host_pointing_at_someone_else(self):
        self.addresses["shop.example.com"] = ["203.0.113.4", "198.51.100.20"]
        self.assertDenied("shop.example.com", "outside the agreed ranges")


class Window(GuardCase):
    def test_before_the_window(self):
        self.now = dt.datetime(2026, 11, 20, 5, 59, tzinfo=UTC)  # 08:59 +03:00
        self.assertDenied("app.example.com", "window opens")

    def test_after_the_window(self):
        self.now = dt.datetime(2026, 11, 27, 15, 1, tzinfo=UTC)  # 18:01 +03:00
        self.assertDenied("app.example.com", "window closed")

    def test_edges_are_inside(self):
        self.now = dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC)
        self.assertAllowed("app.example.com")


class Proof(GuardCase):
    def test_no_record(self):
        self.records.clear()
        self.assertDenied("app.example.com", "no authorization record")

    def test_unrelated_txt_records_are_ignored(self):
        self.records["_scopeguard.example.com"] = ["v=spf1 -all", "hello"]
        self.assertDenied("app.example.com", "no authorization record")

    def test_other_engagement(self):
        self.records["_scopeguard.example.com"] = [self.scope.record_value.replace("ACME-2026-11", "OTHER-1")]
        self.assertDenied("app.example.com", "different engagement")

    def test_wrong_token(self):
        self.records["_scopeguard.example.com"] = [f"v=sg1; id=ACME-2026-11; h={'0' * 64}; exp=2026-11-27"]
        self.assertDenied("app.example.com", "does not match the token")

    def test_expired_record(self):
        value = self.scope.record_value.replace("exp=2026-11-27", "exp=2026-11-21")
        self.records["_scopeguard.example.com"] = [value]
        self.assertDenied("app.example.com", "expired")

    def test_missing_expiry_counts_as_expired(self):
        value = self.scope.record_value.split("; exp=")[0]
        self.records["_scopeguard.example.com"] = [value]
        self.assertDenied("app.example.com", "expired")

    def test_one_good_record_among_others_is_enough(self):
        self.records["_scopeguard.example.com"] = ["v=sg1; id=OLD-1; h=abc; exp=2020-01-01", self.scope.record_value]
        self.assertAllowed("app.example.com")

    def test_range_uses_its_proof_domain(self):
        self.records.clear()
        self.assertDenied("203.0.113.5", "no authorization record at _scopeguard.example.com")

    def test_resolver_failure_denies(self):
        def broken(name):
            raise OSError("timed out")
        verdict = sg.Guard(self.scope, txt_lookup=broken, resolve=lambda host: [],
                           now=lambda: self.now).check("203.0.113.5")
        self.assertFalse(verdict.allowed)
        self.assertIn("could not query", verdict.reason)

    def test_record_value_shape(self):
        fields = sg.parse_record(self.scope.record_value)
        self.assertEqual(fields["v"], "sg1")
        self.assertEqual(fields["id"], "ACME-2026-11")
        self.assertEqual(len(fields["h"]), 64)
        self.assertEqual(fields["exp"], "2026-11-27")
        self.assertNotIn(TOKEN, self.scope.record_value)


class ScopeFile(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            return sg.load_scope(write_scope(tmp, text))

    def test_missing_file(self):
        with self.assertRaisesRegex(sg.ScopeError, "no scope file"):
            sg.load_scope("/nonexistent/scope.toml")

    def test_window_must_carry_an_offset(self):
        with self.assertRaisesRegex(sg.ScopeError, "offset"):
            self.load(SCOPE.replace("2026-11-20T09:00:00+03:00", "2026-11-20T09:00:00"))

    def test_window_order(self):
        with self.assertRaisesRegex(sg.ScopeError, "earlier"):
            self.load(SCOPE.replace("2026-11-27T18:00:00+03:00", "2026-11-19T18:00:00+03:00"))

    def test_range_needs_a_proof_domain(self):
        with self.assertRaisesRegex(sg.ScopeError, "proof"):
            self.load(SCOPE.replace('proof = "example.com"\n', ""))

    def test_target_needs_exactly_one_kind(self):
        with self.assertRaisesRegex(sg.ScopeError, "exactly one"):
            self.load(SCOPE + '\n[[target]]\ndomain = "a.example"\ncidr = "10.0.0.0/8"\nproof = "a.example"\n')

    def test_short_token_and_bad_id(self):
        with self.assertRaisesRegex(sg.ScopeError, "token"):
            self.load(SCOPE.replace(TOKEN, "short"))
        with self.assertRaisesRegex(sg.ScopeError, "engagement.id"):
            self.load(SCOPE.replace("ACME-2026-11", "ACME; 2026"))

    def test_no_targets(self):
        with self.assertRaisesRegex(sg.ScopeError, "no \\[\\[target\\]\\]"):
            self.load(SCOPE.split("[[target]]")[0])


class DnsWire(unittest.TestCase):
    def reply(self, query_id, strings, flags=0x8180, extra=b""):
        question = b"\x0b_scopeguard\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
        answers = b""
        for parts in strings:
            data = b"".join(bytes([len(p)]) + p for p in parts)
            answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(data)) + data
        header = struct.pack(">HHHHHH", query_id, flags, 1, len(strings) + (1 if extra else 0), 0, 0)
        return header + question + extra + answers

    def test_query_layout(self):
        query = sg.build_txt_query("_scopeguard.example.com", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertTrue(query.endswith(b"\x03com\x00" + struct.pack(">HH", 16, 1)))

    def test_txt_strings_are_joined(self):
        reply = self.reply(7, [[b"v=sg1; id=A; ", b"h=abc; exp=2026-01-01"], [b"other"]])
        records, truncated = sg.parse_txt_response(reply, 7)
        self.assertEqual(records, ["v=sg1; id=A; h=abc; exp=2026-01-01", "other"])
        self.assertFalse(truncated)

    def test_other_record_types_are_skipped(self):
        cname = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
        records, _ = sg.parse_txt_response(self.reply(7, [[b"x"]], extra=cname), 7)
        self.assertEqual(records, ["x"])

    def test_nxdomain_truncation_and_errors(self):
        self.assertEqual(sg.parse_txt_response(self.reply(7, [], flags=0x8183), 7), ([], False))
        self.assertEqual(sg.parse_txt_response(self.reply(7, [], flags=0x8380), 7), ([], True))
        with self.assertRaises(OSError):
            sg.parse_txt_response(self.reply(7, [], flags=0x8182), 7)
        with self.assertRaises(ValueError):
            sg.parse_txt_response(self.reply(8, []), 7)
        with self.assertRaises(ValueError):
            sg.parse_txt_response(self.reply(7, [[b"x"]])[:-3] + b"\xff", 7)

    def test_resolver_address_forms(self):
        self.assertEqual(sg._resolver_address("1.1.1.1"), ("1.1.1.1", 53))
        self.assertEqual(sg._resolver_address("127.0.0.1:5353"), ("127.0.0.1", 5353))
        self.assertEqual(sg._resolver_address("2606:4700:4700::1111"), ("2606:4700:4700::1111", 53))
        self.assertEqual(sg._resolver_address("[::1]:5353"), ("::1", 5353))
        with self.assertRaises(ValueError):
            sg._resolver_address("dns.example")


class FakeDns(socketserver.BaseRequestHandler):
    """Answers TXT questions from the server's `zone` dictionary."""

    def handle(self):
        data, sock = self.request
        query_id = struct.unpack(">H", data[:2])[0]
        end = sg._skip_name(data, 12)
        labels, offset = [], 12
        while data[offset]:
            labels.append(data[offset + 1:offset + 1 + data[offset]].decode())
            offset += 1 + data[offset]
        strings = self.server.zone.get(".".join(labels).lower())
        question = data[12:end + 4]
        if strings is None:
            sock.sendto(struct.pack(">HHHHHH", query_id, 0x8183, 1, 0, 0, 0) + question, self.client_address)
            return
        answers = b""
        for text in strings:
            raw = text.encode()
            rdata = b"".join(bytes([len(raw[i:i + 255])]) + raw[i:i + 255] for i in range(0, len(raw), 255))
            answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(rdata)) + rdata
        header = struct.pack(">HHHHHH", query_id, 0x8180, 1, len(strings), 0, 0)
        sock.sendto(header + question + answers, self.client_address)


class CommandLine(unittest.TestCase):
    """The real program against a DNS server on localhost."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        today = dt.datetime.now().astimezone()
        text = SCOPE.replace("2026-11-20T09:00:00+03:00", (today - dt.timedelta(days=1)).isoformat(timespec="seconds"))
        text = text.replace("2026-11-27T18:00:00+03:00", (today + dt.timedelta(days=2)).isoformat(timespec="seconds"))
        # No rule here needs the host's addresses, so the test stays off the real network.
        text = text.replace(', "203.0.113.9"]', "]").replace('resolves_within = ["203.0.113.0/28"]\n', "")
        self.path = write_scope(self.tmp.name, text)
        self.scope = sg.load_scope(self.path)

        self.server = socketserver.UDPServer(("127.0.0.1", 0), FakeDns)
        self.server.zone = {"_scopeguard.example.com": [self.scope.record_value]}
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        previous = os.environ.get("SCOPEGUARD_RESOLVER")
        os.environ["SCOPEGUARD_RESOLVER"] = f"127.0.0.1:{self.server.server_address[1]}"
        self.addCleanup(lambda: os.environ.pop("SCOPEGUARD_RESOLVER") if previous is None
                        else os.environ.__setitem__("SCOPEGUARD_RESOLVER", previous))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sg.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def log(self):
        lines = (Path(self.tmp.name) / "scopeguard.log").read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def test_lookup_over_the_wire(self):
        self.assertEqual(sg.lookup_txt("_scopeguard.example.com"), [self.scope.record_value])
        self.assertEqual(sg.lookup_txt("_scopeguard.nothing.example"), [])

    def test_check_allows_and_denies(self):
        code, out, _ = self.run_cli("check", "-f", str(self.path), "app.example.com", "mail.example.com")
        self.assertEqual(code, sg.EXIT_DENIED)
        self.assertIn("ALLOW  app.example.com", out)
        self.assertIn("DENY   mail.example.com", out)
        self.assertEqual([entry["allowed"] for entry in self.log()], [True, False])

    def test_withdrawing_the_record_stops_the_work(self):
        self.assertEqual(self.run_cli("check", "-f", str(self.path), "app.example.com")[0], 0)
        self.server.zone.clear()
        code, out, _ = self.run_cli("check", "-f", str(self.path), "app.example.com")
        self.assertEqual(code, sg.EXIT_DENIED)
        self.assertIn("no authorization record", out)

    def test_run_executes_with_the_placeholder_filled_in(self):
        marker = Path(self.tmp.name) / "ran.txt"
        program = "import sys, pathlib; pathlib.Path(sys.argv[1]).write_text(sys.argv[2]); sys.exit(5)"
        code, _, err = self.run_cli("run", "-f", str(self.path), "app.example.com", "--",
                                    sys.executable, "-c", program, str(marker), "{}")
        self.assertEqual(code, 5)
        self.assertEqual(marker.read_text(), "app.example.com")
        self.assertIn("ALLOW", err)
        events = self.log()
        self.assertEqual([e["event"] for e in events], ["run", "exit"])
        self.assertEqual(events[1]["code"], 5)
        self.assertNotIn(TOKEN, json.dumps(events))

    def test_run_refuses_out_of_scope_targets(self):
        marker = Path(self.tmp.name) / "ran.txt"
        program = "import sys, pathlib; pathlib.Path(sys.argv[1]).write_text('x')"
        code, _, err = self.run_cli("run", "-f", str(self.path), "evilexample.com", "--",
                                    sys.executable, "-c", program, str(marker), "{}")
        self.assertEqual(code, sg.EXIT_DENIED)
        self.assertFalse(marker.exists())
        self.assertIn("DENY", err)
        self.assertEqual(self.log()[0]["event"], "deny")

    def test_run_refuses_a_command_that_names_another_target(self):
        marker = Path(self.tmp.name) / "ran.txt"
        program = "import sys, pathlib; pathlib.Path(sys.argv[1]).write_text('x')"
        code, _, err = self.run_cli("run", "-f", str(self.path), "app.example.com", "--",
                                    sys.executable, "-c", program, str(marker), "other.example.org")
        self.assertEqual(code, sg.EXIT_DENIED)
        self.assertFalse(marker.exists())
        self.assertIn("does not appear in the command", err)

    def test_run_without_a_command(self):
        self.assertEqual(self.run_cli("run", "-f", str(self.path), "app.example.com")[0], sg.EXIT_CONFIG)

    def test_status(self):
        code, out, _ = self.run_cli("status", "-f", str(self.path))
        self.assertEqual(code, 0)
        self.assertIn("window      open", out)
        self.assertIn("proof       ok", out)
        self.server.zone.clear()
        self.assertEqual(self.run_cli("status", "-f", str(self.path))[0], sg.EXIT_DENIED)

    def test_init_writes_a_private_loadable_file(self):
        path = Path(self.tmp.name) / "new" / "scope.toml"
        path.parent.mkdir()
        code, out, _ = self.run_cli("init", "-f", str(path), "ACME-2027-01", "Example.org", "--client", "ACME")
        self.assertEqual(code, 0)
        scope = sg.load_scope(path)
        self.assertEqual(scope.targets[0].domain, "example.org")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn(f"_scopeguard.example.org", out)
        self.assertIn(scope.record_value, out)
        self.assertNotIn(scope.token, out)
        self.assertEqual(self.run_cli("init", "-f", str(path), "ACME-2027-01", "example.org")[0], sg.EXIT_CONFIG)

    def test_missing_scope_file_is_a_configuration_error(self):
        code, _, err = self.run_cli("check", "-f", str(Path(self.tmp.name) / "none.toml"), "example.com")
        self.assertEqual(code, sg.EXIT_CONFIG)
        self.assertIn("no scope file", err)


if __name__ == "__main__":
    unittest.main()
