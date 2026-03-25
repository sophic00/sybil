#!/usr/bin/env python3
"""Generate multiple distinct TLS ClientHello profiles against a local TLS endpoint.

This script is designed for JA4 demos where you want N logical clients and each client
hits the same endpoint M times while producing different ClientHello fingerprints.

It uses `openssl s_client` with different TLS settings (version, ALPN, ciphers,
groups, signature algorithms, and SNI), which changes JA4-relevant fields.
"""

from __future__ import annotations

import argparse
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class TLSProfile:
    name: str
    openssl_args: List[str]


# Intentionally varied across JA4-relevant dimensions.
# Some combinations may fail to fully handshake on a given server, but ClientHello
# is still sent on the wire (useful for packet-capture demos).
PROFILES: List[TLSProfile] = [
    TLSProfile("tls13_h2_x25519", ["-tls1_3", "-alpn", "h2", "-groups", "X25519", "-ciphersuites", "TLS_AES_128_GCM_SHA256"]),
    TLSProfile("tls13_h1_p256", ["-tls1_3", "-alpn", "http/1.1", "-groups", "P-256", "-ciphersuites", "TLS_AES_256_GCM_SHA384"]),
    TLSProfile("tls13_h2_h1_mixed", ["-tls1_3", "-alpn", "h2,http/1.1", "-groups", "X25519:P-256", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"]),
    TLSProfile("tls13_custom_sigalgs", ["-tls1_3", "-alpn", "h2", "-groups", "X25519", "-sigalgs", "rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"]),
    TLSProfile("tls13_no_alpn", ["-tls1_3", "-groups", "X25519", "-ciphersuites", "TLS_AES_128_GCM_SHA256"]),
    TLSProfile("tls12_ecdsa_gcm", ["-tls1_2", "-alpn", "h2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256", "-sigalgs", "ecdsa_secp256r1_sha256"]),
    TLSProfile("tls12_rsa_gcm", ["-tls1_2", "-alpn", "http/1.1", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-sigalgs", "rsa_pkcs1_sha256"]),
    TLSProfile("tls12_rsa_chacha", ["-tls1_2", "-alpn", "http/1.1", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-groups", "X25519"]),
    TLSProfile("tls12_legacy_aes", ["-tls1_2", "-cipher", "AES128-SHA", "-groups", "P-256"]),
    TLSProfile("tls12_legacy_3des", ["-tls1_2", "-cipher", "DES-CBC3-SHA", "-groups", "P-256"]),
    TLSProfile("tls13_alt_group", ["-tls1_3", "-alpn", "h2", "-groups", "P-384", "-ciphersuites", "TLS_AES_128_GCM_SHA256"]),
    TLSProfile("tls12_h2_x448", ["-tls1_2", "-alpn", "h2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-groups", "X448"]),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hit a TLS endpoint with N distinct OpenSSL client profiles, each M times.",
    )
    parser.add_argument("-n", "--clients", type=int, default=10, help="Number of distinct client profiles to use (default: 10)")
    parser.add_argument("-m", "--repeats", type=int, default=3, help="How many times each client profile hits endpoint (default: 3)")
    parser.add_argument("--host", default="127.0.0.1", help="Target host/IP for connect (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Target TLS port (default: 8443)")
    parser.add_argument("--sni", default="localhost", help="SNI value for ClientHello (default: localhost)")
    parser.add_argument("--http-host", default=None, help="HTTP Host header value (default: same as --sni)")
    parser.add_argument("--path", default="/", help="HTTP path sent after handshake (default: /)")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay in seconds between requests (default: 0.25)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout seconds per request (default: 8)")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle selected profiles before sending")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if shutil.which("openssl") is None:
        print("ERROR: openssl not found in PATH.", file=sys.stderr)
        sys.exit(2)

    if args.clients < 1:
        print("ERROR: --clients must be >= 1.", file=sys.stderr)
        sys.exit(2)

    if args.repeats < 1:
        print("ERROR: --repeats must be >= 1.", file=sys.stderr)
        sys.exit(2)

    if args.clients > len(PROFILES):
        print(
            f"ERROR: Requested {args.clients} clients but only {len(PROFILES)} distinct profiles are defined.",
            file=sys.stderr,
        )
        sys.exit(2)


def build_command(profile: TLSProfile, host: str, port: int, sni: str) -> List[str]:
    return [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        sni,
        "-verify_quiet",
        "-quiet",
        *profile.openssl_args,
    ]


def run_once(profile: TLSProfile, args: argparse.Namespace) -> tuple[bool, str]:
    cmd = build_command(profile, args.host, args.port, args.sni)
    host_header = args.http_host or args.sni
    request = (
        f"GET {args.path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "User-Agent: ja4-client-matrix/1.0\r\n"
        "\r\n"
    )

    if args.dry_run:
        return True, "DRY-RUN"

    try:
        completed = subprocess.run(
            cmd,
            input=request,
            text=True,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"

    err = (completed.stderr or "").lower()
    out = (completed.stdout or "").lower()

    # Even if the server rejects later, ClientHello is usually already sent.
    if completed.returncode == 0:
        return True, "ok"

    # Local demo servers are often self-signed; that should still count as a
    # successful TLS handshake for JA4 capture purposes.
    if "self-signed certificate" in err or "verify return code: 18" in err or "self-signed certificate" in out:
        return True, "ok_self_signed"

    if "handshake failure" in err or "alert" in err or "no shared cipher" in err:
        return False, "handshake_failed_after_clienthello"

    return False, f"exit_{completed.returncode}"


def main() -> int:
    args = parse_args()
    validate_args(args)

    selected = list(PROFILES[: args.clients])
    if args.shuffle:
        random.shuffle(selected)

    total = args.clients * args.repeats
    print(f"Target: {args.host}:{args.port}  SNI={args.sni}  path={args.path}")
    print(f"Profiles: {args.clients}  Repeats: {args.repeats}  Total attempts: {total}")
    print("-" * 80)

    ok_count = 0
    fail_count = 0
    per_profile = {p.name: {"ok": 0, "fail": 0} for p in selected}

    sent = 0
    for rep in range(1, args.repeats + 1):
        for idx, profile in enumerate(selected, start=1):
            sent += 1
            print(f"[{sent}/{total}] rep={rep} client={idx}/{args.clients} profile={profile.name}", end=" ")
            success, reason = run_once(profile, args)
            if success:
                ok_count += 1
                per_profile[profile.name]["ok"] += 1
                print(f"-> OK ({reason})")
            else:
                fail_count += 1
                per_profile[profile.name]["fail"] += 1
                print(f"-> FAIL ({reason})")

            time.sleep(args.delay)

    print("-" * 80)
    print(f"Done. OK={ok_count} FAIL={fail_count}")
    print("Per-profile:")
    for profile in selected:
        stats = per_profile[profile.name]
        print(f"  - {profile.name}: ok={stats['ok']} fail={stats['fail']}")

    if fail_count > 0:
        print(
            "\nNote: FAIL can still be useful for JA4/pcap demos because ClientHello is usually emitted before failure.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
