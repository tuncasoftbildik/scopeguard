#!/usr/bin/env python3
"""scopeguard: refuse to test what you are not authorized to test.

A scan only runs when three things hold at the same moment:

  1. the target is inside the scope agreed for this engagement,
  2. the agreed time window is open,
  3. the owner still publishes a DNS TXT record that vouches for the engagement.

Standard library only. Python 3.11+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

__version__ = "0.1.0"

RECORD_LABEL = "_scopeguard"
RECORD_VERSION = "sg1"
EXIT_CONFIG = 2
EXIT_DENIED = 3

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeError(Exception):
    """The scope file is missing or does not make sense."""


# --------------------------------------------------------------------------
# Scope file
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    domain: str | None
    network: Network | None
    proof: str
    exclude_hosts: tuple[str, ...] = ()
    exclude_nets: tuple[Network, ...] = ()
    resolves_within: tuple[Network, ...] = ()

    @property
    def label(self) -> str:
        return self.domain if self.domain else str(self.network)


@dataclass(frozen=True)
class Scope:
    id: str
    client: str
    token: str
    not_before: dt.datetime
    not_after: dt.datetime
    targets: tuple[Target, ...]
    path: Path | None = None

    @property
    def token_hash(self) -> str:
        return hashlib.sha256(self.token.encode("utf-8")).hexdigest()

    @property
    def proof_domains(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(t.proof for t in self.targets))

    @property
    def record_value(self) -> str:
        expires = self.not_after.astimezone(dt.timezone.utc).date().isoformat()
        return f"v={RECORD_VERSION}; id={self.id}; h={self.token_hash}; exp={expires}"


def normalise_host(value: str) -> str:
    host = str(value).strip().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{value!r} is not a valid host name") from exc
    labels = host.split(".")
    if not host or len(host) > 253 or not all(re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in labels):
        raise ValueError(f"{value!r} is not a valid host name")
    return host


def _target_entry(index: int, entry: dict) -> Target:
    domain, cidr = entry.get("domain"), entry.get("cidr")
    if bool(domain) == bool(cidr):
        raise ScopeError(f"target #{index}: give exactly one of domain or cidr")
    try:
        hosts, nets = [], []
        for item in entry.get("exclude", []):
            try:
                nets.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                hosts.append(normalise_host(item))
        within = tuple(ipaddress.ip_network(str(x), strict=False) for x in entry.get("resolves_within", []))
        if domain:
            name = normalise_host(domain)
            proof = normalise_host(entry.get("proof", name))
            return Target(name, None, proof, tuple(hosts), tuple(nets), within)
        if not entry.get("proof"):
            raise ScopeError(f'target #{index}: a cidr target needs proof = "<domain>", '
                             "the domain whose TXT record vouches for the range")
        network = ipaddress.ip_network(str(cidr), strict=False)
        return Target(None, network, normalise_host(entry["proof"]), tuple(hosts), tuple(nets), within)
    except ValueError as exc:
        raise ScopeError(f"target #{index}: {exc}") from exc


def load_scope(path: str | os.PathLike) -> Scope:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScopeError(f"{path}: no scope file here (create one with `scopeguard init`)") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScopeError(f"{path}: {exc}") from exc

    engagement = data.get("engagement") or {}
    ident = str(engagement.get("id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", ident):
        raise ScopeError("engagement.id must be 1-64 characters from A-Z a-z 0-9 . _ -")
    token = str(engagement.get("token", ""))
    if len(token) < 16:
        raise ScopeError("engagement.token is missing or shorter than 16 characters")
    window = []
    for key in ("not_before", "not_after"):
        value = engagement.get(key)
        if not isinstance(value, dt.datetime) or value.tzinfo is None:
            raise ScopeError(f"engagement.{key} must be a date-time with an offset, "
                             "for example 2026-11-20T09:00:00+03:00")
        window.append(value)
    if window[0] >= window[1]:
        raise ScopeError("engagement.not_before must be earlier than not_after")
    entries = data.get("target") or []
    if not entries:
        raise ScopeError("the scope file has no [[target]] entries")
    targets = tuple(_target_entry(i, entry) for i, entry in enumerate(entries, 1))
    return Scope(ident, str(engagement.get("client", "")), token, window[0], window[1], targets, path)


# --------------------------------------------------------------------------
# DNS (TXT lookups without third-party packages)
# --------------------------------------------------------------------------

def system_resolvers() -> list[str]:
    override = os.environ.get("SCOPEGUARD_RESOLVER")
    if override:
        return [item.strip() for item in override.split(",") if item.strip()]
    found = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                found.append(parts[1])
    except OSError:
        pass
    return found or ["1.1.1.1"]


def _resolver_address(spec: str) -> tuple[str, int]:
    """Accept 1.1.1.1, 1.1.1.1:5353, 2606:4700:4700::1111 and [::1]:5353."""
    spec, port = spec.strip(), 53
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif spec.count(":") == 1:
        host, _, tail = spec.partition(":")
        port = int(tail)
    else:
        host = spec
    ipaddress.ip_address(host.split("%")[0])
    return host, port


def build_txt_query(name: str, query_id: int) -> bytes:
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 16, 1)


def _skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return offset + 2
        offset += 1 + length


def parse_txt_response(message: bytes, query_id: int) -> tuple[list[str], bool]:
    """Return (TXT strings, truncated). Raises ValueError or OSError on a bad reply."""
    try:
        reply_id, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", message[:12])
        if reply_id != query_id:
            raise ValueError("DNS reply does not match the query")
        rcode = flags & 0x000F
        if rcode == 3:  # NXDOMAIN
            return [], False
        if rcode != 0:
            raise OSError(f"DNS server answered with error code {rcode}")
        if flags & 0x0200:
            return [], True
        offset = 12
        for _ in range(questions):
            offset = _skip_name(message, offset) + 4
        records = []
        for _ in range(answers):
            offset = _skip_name(message, offset)
            rtype, _, _, length = struct.unpack(">HHIH", message[offset:offset + 10])
            offset += 10
            data = message[offset:offset + length]
            if len(data) != length:
                raise ValueError("malformed DNS reply")
            offset += length
            if rtype != 16:
                continue
            chunks, position = [], 0
            while position < len(data):
                size = data[position]
                chunk = data[position + 1:position + 1 + size]
                if len(chunk) != size:
                    raise ValueError("malformed DNS reply")
                chunks.append(chunk)
                position += 1 + size
            records.append(b"".join(chunks).decode("utf-8", "replace"))
        return records, False
    except (struct.error, IndexError) as exc:
        raise ValueError("malformed DNS reply") from exc


def _read_tcp(sock: socket.socket) -> bytes:
    def read(count: int) -> bytes:
        buffer = b""
        while len(buffer) < count:
            chunk = sock.recv(count - len(buffer))
            if not chunk:
                raise OSError("DNS server closed the connection")
            buffer += chunk
        return buffer
    return read(struct.unpack(">H", read(2))[0])


def lookup_txt(name: str, resolvers: list[str] | None = None, timeout: float = 3.0) -> list[str]:
    """All TXT strings published at `name`; an empty list when there are none."""
    last_error: Exception | None = None
    for spec in resolvers or system_resolvers():
        try:
            host, port = _resolver_address(spec)
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            query_id = secrets.randbelow(65536)
            query = build_txt_query(name, query_id)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (host, port))
                reply, _ = sock.recvfrom(4096)
            records, truncated = parse_txt_response(reply, query_id)
            if truncated:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    sock.sendall(struct.pack(">H", len(query)) + query)
                    records, _ = parse_txt_response(_read_tcp(sock), query_id)
            return records
        except (OSError, ValueError) as exc:
            last_error = exc
    raise OSError(f"no DNS resolver answered for {name} ({last_error})")


def resolve_host(host: str) -> list[Address]:
    infos = socket.getaddrinfo(host, None)
    return sorted({ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}, key=str)


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    allowed: bool
    target: str
    reason: str

    def __str__(self) -> str:
        return f"{'ALLOW' if self.allowed else 'DENY '}  {self.target}  {self.reason}"


def parse_target(raw: str) -> tuple[str | None, Network | None]:
    """Read a host name, URL, address or CIDR range. Returns (host, network)."""
    text = raw.strip()
    if "://" not in text:
        try:
            return None, ipaddress.ip_network(text.strip("[]"), strict=False)
        except ValueError:
            pass
    try:
        host = urlsplit(text if "://" in text else "//" + text).hostname
    except ValueError:
        host = None
    if not host:
        raise ValueError(f"cannot read a host from {raw!r}")
    try:
        return None, ipaddress.ip_network(host, strict=False)
    except ValueError:
        return normalise_host(host), None


def parse_record(text: str) -> dict[str, str]:
    fields = {}
    for part in text.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            fields[key.strip().lower()] = value.strip()
    return fields


def _within(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _same_family(a: Network, b: Network) -> bool:
    return a.version == b.version


class Guard:
    """Decides whether a target may be tested right now."""

    def __init__(self, scope: Scope, txt_lookup=None, resolve=None, now=None):
        self.scope = scope
        self._txt_lookup = txt_lookup or lookup_txt
        self._resolve = resolve or resolve_host
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._proofs: dict[str, tuple[bool, str]] = {}

    def window(self) -> tuple[bool, str]:
        now = self._now()
        if now < self.scope.not_before:
            return False, f"the agreed window opens at {self.scope.not_before.isoformat()}"
        if now > self.scope.not_after:
            return False, f"the agreed window closed at {self.scope.not_after.isoformat()}"
        return True, f"until {self.scope.not_after.isoformat()}"

    def proof(self, domain: str) -> tuple[bool, str]:
        if domain not in self._proofs:
            self._proofs[domain] = self._check_proof(domain)
        return self._proofs[domain]

    def _check_proof(self, domain: str) -> tuple[bool, str]:
        name = f"{RECORD_LABEL}.{domain}"
        try:
            records = [parse_record(text) for text in self._txt_lookup(name)]
        except OSError as exc:
            return False, f"could not query {name}: {exc}"
        records = [r for r in records if r.get("v") == RECORD_VERSION]
        if not records:
            return False, f"no authorization record at {name}"
        records = [r for r in records if r.get("id") == self.scope.id]
        if not records:
            return False, f"the record at {name} is for a different engagement"
        records = [r for r in records if hmac.compare_digest(r.get("h", ""), self.scope.token_hash)]
        if not records:
            return False, f"the record at {name} does not match the token in this scope file"
        today = self._now().astimezone(dt.timezone.utc).date()
        for record in records:
            try:
                if dt.date.fromisoformat(record.get("exp", "")) >= today:
                    return True, f"proof at {name}"
            except ValueError:
                continue
        return False, f"the authorization record at {name} has expired"

    def _match(self, host: str | None, network: Network | None) -> tuple[Target | None, str]:
        if network is not None:
            for target in self.scope.targets:
                inside = (target.network is not None and _same_family(network, target.network)
                          and network.subnet_of(target.network))
                if inside:
                    if any(_same_family(network, e) and network.overlaps(e) for e in target.exclude_nets):
                        return None, "explicitly excluded from scope"
                    return target, ""
            return None, "not inside any agreed range"
        candidates = [t for t in self.scope.targets if t.domain and _within(host, t.domain)]
        if not candidates:
            return None, "not in the agreed scope"
        target = max(candidates, key=lambda t: len(t.domain))
        if any(_within(host, excluded) for excluded in target.exclude_hosts):
            return None, "explicitly excluded from scope"
        return target, ""

    def check(self, raw: str) -> Verdict:
        try:
            host, network = parse_target(raw)
        except ValueError as exc:
            return Verdict(False, raw, str(exc))
        if host:
            name = host
        else:
            single = network.prefixlen == network.max_prefixlen
            name = str(network.network_address) if single else str(network)

        is_open, why = self.window()
        if not is_open:
            return Verdict(False, name, why)
        target, why = self._match(host, network)
        if target is None:
            return Verdict(False, name, why)

        if host and (target.resolves_within or target.exclude_nets):
            try:
                addresses = self._resolve(host)
            except OSError as exc:
                return Verdict(False, name, f"cannot resolve {host}: {exc}")
            for address in addresses:
                if any(address in net for net in target.exclude_nets):
                    return Verdict(False, name, f"resolves to {address}, which is excluded from scope")
                if target.resolves_within and not any(address in net for net in target.resolves_within):
                    return Verdict(False, name, f"resolves to {address}, outside the agreed ranges "
                                                "(third-party hosting?)")
            if not addresses:
                return Verdict(False, name, f"{host} does not resolve")

        proven, why = self.proof(target.proof)
        if not proven:
            return Verdict(False, name, why)
        return Verdict(True, name, f"in scope for {self.scope.id}; {why}")


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------

def log_path(scope: Scope) -> Path:
    base = scope.path.parent if scope.path else Path.cwd()
    return base / "scopeguard.log"


def write_log(scope: Scope, event: str, **fields) -> None:
    entry = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "engagement": scope.id, "event": event, **fields}
    with log_path(scope).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

SCOPE_TEMPLATE = '''# scopeguard scope file. Keep it private: the token proves you are the tester
# the owner agreed to. The owner publishes only the SHA-256 of the token.

[engagement]
id = "{ident}"
client = "{client}"
token = "{token}"
not_before = {start}
not_after = {end}

{targets}
# More examples:
#
# [[target]]
# domain = "example.com"                 # the domain and every subdomain
# exclude = ["mail.example.com"]         # never touch these
# resolves_within = ["203.0.113.0/28"]   # deny if DNS points anywhere else
#
# [[target]]
# cidr = "203.0.113.0/28"
# proof = "example.com"                  # whose TXT record vouches for the range
'''


def print_records(scope: Scope) -> None:
    print("Ask the owner to publish this DNS TXT record before the window opens:\n")
    for domain in scope.proof_domains:
        print(f"  name   {RECORD_LABEL}.{domain}")
        print(f"  type   TXT")
        print(f"  value  {scope.record_value}\n")
    print("Deleting the record withdraws the authorization at once.")


def cmd_init(args) -> int:
    path = Path(args.file)
    if path.exists():
        print(f"scopeguard: {path} already exists", file=sys.stderr)
        return EXIT_CONFIG
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args.id):
        print("scopeguard: the engagement id must be 1-64 characters from A-Z a-z 0-9 . _ -", file=sys.stderr)
        return EXIT_CONFIG
    try:
        domains = [normalise_host(d) for d in args.domain]
    except ValueError as exc:
        print(f"scopeguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    start =dt.datetime.now().astimezone().replace(second=0, microsecond=0)
    end = start + dt.timedelta(days=args.days)
    targets = "".join(f'[[target]]\ndomain = "{d}"\n\n' for d in domains)
    path.write_text(SCOPE_TEMPLATE.format(
        ident=args.id, client=args.client.replace('"', "'"), token="sg_" + secrets.token_urlsafe(24),
        start=start.isoformat(timespec="seconds"), end=end.isoformat(timespec="seconds"),
        targets=targets), encoding="utf-8")
    os.chmod(path, 0o600)
    scope = load_scope(path)
    print(f"Wrote {path} (window: {args.days} days from now; edit it to match the signed agreement).\n")
    print_records(scope)
    return 0


def cmd_record(args) -> int:
    print_records(load_scope(args.file))
    return 0


def cmd_status(args) -> int:
    scope = load_scope(args.file)
    guard = Guard(scope)
    is_open, why = guard.window()
    print(f"engagement  {scope.id}" + (f"  ({scope.client})" if scope.client else ""))
    print(f"window      {'open' if is_open else 'CLOSED'}: {why}")
    healthy = is_open
    for domain in scope.proof_domains:
        proven, why = guard.proof(domain)
        healthy = healthy and proven
        print(f"proof       {'ok' if proven else 'MISSING'}: {why}")
    for target in scope.targets:
        excluded = [str(item) for item in target.exclude_hosts + target.exclude_nets]
        print(f"target      {target.label}" + (f"  (excluding {', '.join(excluded)})" if excluded else ""))
    return 0 if healthy else EXIT_DENIED


def cmd_check(args) -> int:
    scope = load_scope(args.file)
    guard = Guard(scope)
    worst = 0
    for raw in args.target:
        verdict = guard.check(raw)
        write_log(scope, "check", target=verdict.target, allowed=verdict.allowed, reason=verdict.reason)
        print(verdict)
        if not verdict.allowed:
            worst = EXIT_DENIED
    return worst


def cmd_run(args) -> int:
    scope = load_scope(args.file)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("scopeguard: nothing to run; usage: scopeguard run TARGET -- COMMAND [ARGS...]", file=sys.stderr)
        return EXIT_CONFIG

    verdict = Guard(scope).check(args.target)
    if verdict.allowed:
        if any("{}" in part for part in command):
            command = [part.replace("{}", args.target) for part in command]
        elif not any(args.target in part for part in command):
            verdict = Verdict(False, verdict.target,
                              "the checked target does not appear in the command; write {} where it belongs")
    if not verdict.allowed:
        write_log(scope, "deny", target=verdict.target, reason=verdict.reason, command=command)
        print(verdict, file=sys.stderr)
        return EXIT_DENIED

    write_log(scope, "run", target=verdict.target, reason=verdict.reason, command=command)
    print(verdict, file=sys.stderr)
    environment = dict(os.environ, SCOPEGUARD_ENGAGEMENT=scope.id, SCOPEGUARD_TARGET=verdict.target)
    try:
        code = subprocess.run(command, env=environment).returncode
    except FileNotFoundError:
        print(f"scopeguard: command not found: {command[0]}", file=sys.stderr)
        code = 127
    write_log(scope, "exit", target=verdict.target, code=code)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopeguard", description="Refuse to test what you are not authorized to test.")
    parser.add_argument("--version", action="version", version=f"scopeguard {__version__}")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("-f", "--file", default=os.environ.get("SCOPEGUARD_SCOPE", "scope.toml"),
                        help="scope file (default: scope.toml, or $SCOPEGUARD_SCOPE)")
    commands = parser.add_subparsers(dest="command_name", required=True)

    init = commands.add_parser("init", parents=[shared], help="create a scope file and print the DNS record")
    init.add_argument("id", help="engagement id, for example ACME-2026-11")
    init.add_argument("domain", nargs="+", help="domain(s) in scope")
    init.add_argument("--client", default="", help="client name, for the record")
    init.add_argument("--days", type=int, default=7, help="length of the window in days (default: 7)")
    init.set_defaults(handler=cmd_init)

    record = commands.add_parser("record", parents=[shared], help="print the DNS record the owner must publish")
    record.set_defaults(handler=cmd_record)

    status = commands.add_parser("status", parents=[shared], help="show the window and the proof records")
    status.set_defaults(handler=cmd_status)

    check = commands.add_parser("check", parents=[shared], help="say whether targets may be tested right now")
    check.add_argument("target", nargs="+", help="host name, URL, address or CIDR range")
    check.set_defaults(handler=cmd_check)

    run = commands.add_parser("run", parents=[shared], help="run a command only if the target is authorized")
    run.add_argument("target", help="host name, URL, address or CIDR range")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]; {} is replaced by the target")
    run.set_defaults(handler=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except ScopeError as exc:
        print(f"scopeguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
