# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Ed25519 written out from RFC 8032, with no library.

Not a test file and not used by the node. It exists to build, from first
principles, the signatures on which implementations of Ed25519 disagree
(points of small or mixed order, encodings that are not canonical, a
nonce point equal to the identity), and to give two verdicts on each: the
one of the rule Kern fixes (docs/hybrid-signatures.md, section 2.5),
computed here as plain mathematics, and the one of a lenient verifier.
The cases are kept in tests/vectors/kern/ed25519_edge_cases.json; running
this file rebuilds them.

Slow and not constant time: this is tooling, never to be used to sign.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)
Point = tuple[int, int]


def add(a: Point, b: Point) -> Point:
    (x1, y1), (x2, y2) = a, b
    k = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + k, P - 2, P) % P,
            (y1 * y2 + x1 * x2) * pow(1 - k, P - 2, P) % P)


def neg(a: Point) -> Point:
    return ((-a[0]) % P, a[1])


def mul(n: int, a: Point) -> Point:
    result, addend = IDENTITY, a
    while n > 0:
        if n & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        n >>= 1
    return result


def recover_x(y: int, sign: int) -> int | None:
    """x for a reduced y, or None if no point of the curve has this y."""
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None
    return x if x & 1 == sign else (-x) % P


def encode(a: Point, *, noncanonical_y: bool = False, flip_sign: bool = False) -> bytes:
    """The 32-byte encoding. `noncanonical_y` writes y + p (possible only
    for y < 19); `flip_sign` sets the wrong sign bit (it only gives another
    encoding of the same point when x is 0)."""
    x, y = a
    if noncanonical_y:
        assert y < 19
        y += P
    return (y | (((x & 1) ^ int(flip_sign)) << 255)).to_bytes(32, "little")


def decode_leniently(b: bytes) -> Point | None:
    """Decode as the most lenient implementations do: y reduced modulo p,
    and x = 0 accepted with either sign bit. None if not on the curve."""
    n = int.from_bytes(b, "little")
    y = (n & (2**255 - 1)) % P
    x = recover_x(y, n >> 255)
    return None if x is None else (x, y)


_BY = 4 * pow(5, P - 2, P) % P
_BX = recover_x(_BY, 0)
assert _BX is not None
B: Point = (_BX, _BY)


def order(a: Point) -> int:
    for n in (1, 2, 4, 8, L, 2 * L, 4 * L, 8 * L):
        if mul(n, a) == IDENTITY:
            return n
    raise AssertionError("not a point of the curve")


def torsion_points() -> list[Point]:
    """The eight points whose order divides 8."""
    y = 2
    while True:
        x = recover_x(y, 0)
        if x is not None:
            t = mul(L, (x, y))
            if order(t) == 8:
                return sorted({mul(i, t) for i in range(8)}, key=lambda pt: (order(pt), pt[1], pt[0]))
        y += 1


def _sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    return encode(mul(secret_scalar(seed)[0], B))


def sign(seed: bytes, message: bytes) -> bytes:
    """The deterministic signature of RFC 8032, section 5.1.6."""
    a, prefix = secret_scalar(seed)
    pk = encode(mul(a, B))
    r = _sha512_int(prefix, message) % L
    r_enc = encode(mul(r, B))
    return r_enc + ((r + challenge(r_enc, pk, message) * a) % L).to_bytes(32, "little")


def challenge(r_enc: bytes, pk: bytes, message: bytes) -> int:
    return _sha512_int(r_enc, pk, message) % L


def decode_strictly(b: bytes) -> Point | None:
    """Decode as RFC 8032, section 5.1.3, requires: None unless `b` is the
    one encoding of a point of the curve (y below p, and no sign bit when
    x is 0)."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign, y = n >> 255, n & (2**255 - 1)
    if y >= P:
        return None
    x = recover_x(y, sign)
    if x is None or x & 1 != sign:
        return None
    return (x, y)


def strict_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """The rule of Kern, as mathematics and with no library:
    1. a public key A of 32 bytes and a signature of 64 bytes, R then S;
    2. A is the canonical encoding of a point of the subgroup of prime
       order, and is not the identity;
    3. R is the canonical encoding of a point, and is not the identity;
    4. S is below the order of the group;
    5. [S]B = R + [k]A, exactly.
    With 2 and 5, R is in the subgroup of prime order too."""
    if len(pk) != 32 or len(signature) != 64:
        return False
    a, r = decode_strictly(pk), decode_strictly(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L:
        return False
    if a == IDENTITY or mul(L, a) != IDENTITY or r == IDENTITY:
        return False
    return mul(s, B) == add(r, mul(challenge(signature[:32], pk, message), a))


def lenient_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """What a verifier answers when it only makes the checks RFC 8032
    requires and compares the bytes of R: S below the group order, points
    decoded leniently, [S]B - [k]A encoded and compared with R. Small
    orders are not looked at. The standard library of Go and OpenSSL
    answer this way on every case of this file."""
    if len(pk) != 32 or len(signature) != 64:
        return False
    a = decode_leniently(pk)
    s = int.from_bytes(signature[32:], "little")
    if a is None or s >= L:
        return False
    k = challenge(signature[:32], pk, message)
    return encode(add(mul(s, B), neg(mul(k, a)))) == signature[:32]


# ---------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------

def build_cases() -> list[dict]:
    """31 signatures, each with the reason it is there. Deterministic."""
    seed = hashlib.sha512(b"kern ed25519 edge cases").digest()[:32]
    a_scalar, _ = secret_scalar(seed)
    a_point = mul(a_scalar, B)
    a_enc = encode(a_point)
    torsion = torsion_points()
    t8 = next(t for t in torsion if order(t) == 8)
    zero = bytes(32)
    cases: list[dict] = []

    def s_bytes(s: int) -> bytes:
        return s.to_bytes(32, "little")

    def case(name: str, pk: bytes, message: bytes, sig: bytes, comment: str) -> None:
        cases.append({"name": name, "public_key": pk.hex(), "message": message.hex(),
                      "signature": sig.hex(), "comment": comment})

    def first_message(predicate, tag: bytes) -> bytes:
        for i in range(100000):
            m = tag + b" " + str(i).encode()
            if predicate(m):
                return m
        raise AssertionError(tag)

    # Controls.
    honest = sign(seed, b"kern")
    case("honest", a_enc, b"kern", honest, "An ordinary signature.")
    case("honest, another message", a_enc, b"kern!", honest,
         "An ordinary signature, checked against another message.")

    # S that is not canonical.
    s = int.from_bytes(honest[32:], "little")
    case("S plus the group order", a_enc, b"kern", honest[:32] + s_bytes(s + L),
         "The scalar S of a valid signature replaced by S + L: the same value "
         "modulo the group order, another encoding.")
    case("S with the top bits set", a_enc, b"kern", honest[:32] + s_bytes(s | (0xE0 << 248)),
         "The scalar S of a valid signature with its three top bits set.")

    # A public key of small order, with S = 0.
    for a_pt in torsion:
        same_order = [t for t in torsion if order(t) == order(a_pt)]
        which = f", point {same_order.index(a_pt) + 1}" if len(same_order) > 1 else ""
        encodings = [("canonical", encode(a_pt))]
        if a_pt[0] == 0:
            encodings.append(("sign bit set although x is 0", encode(a_pt, flip_sign=True)))
        if a_pt[1] < 19:
            encodings.append(("y written as y + p", encode(a_pt, noncanonical_y=True)))
        for label, pk in encodings:
            found = None
            for i in range(4000):
                m = b"kern small order " + str(i).encode()
                for r_pt in torsion:
                    r_enc = encode(r_pt)
                    if add(r_pt, mul(challenge(r_enc, pk, m), a_pt)) == IDENTITY:
                        found = (m, r_enc, order(r_pt))
                        break
                if found:
                    break
            assert found is not None
            m, r_enc, r_order = found
            case(f"public key of order {order(a_pt)}{which} ({label}), R of order {r_order}, S zero",
                 pk, m, r_enc + zero,
                 "Nobody holds a secret for this key. [S]B = R + [k]A holds because "
                 "everything lies in the small subgroup.")

    # An honest key and a nonce point that is the identity: S = k a.
    m = b"kern identity R"
    for label, r_enc, comment in (
            ("", encode(IDENTITY), "Made by the key holder with the nonce 0. [S]B = R + [k]A holds exactly, "
                                   "and S / k is the secret scalar: such a signature gives the key away."),
            (" written as p + 1", encode(IDENTITY, noncanonical_y=True),
             "The same with the identity encoded as y = p + 1."),
            (" with the sign bit set", encode(IDENTITY, flip_sign=True),
             "The same with the sign bit set although x is 0.")):
        k = challenge(r_enc, a_enc, m)
        case("honest key, R is the identity" + label, a_enc, m, r_enc + s_bytes(k * a_scalar % L), comment)

    # An honest key and R of order 8: holds only once multiplied by the cofactor.
    r_enc = encode(t8)
    k = challenge(r_enc, a_enc, m)
    case("honest key, R of order 8", a_enc, m, r_enc + s_bytes(k * a_scalar % L),
         "8[S]B = 8R + 8[k]A holds, [S]B = R + [k]A does not.")

    # A public key of mixed order: an ordinary key plus a point of order 8.
    mixed = encode(add(a_point, t8))
    r = 0x1234567890ABCDEF1234567890ABCDEF % L
    r_enc = encode(mul(r, B))
    m0 = first_message(lambda msg: challenge(r_enc, mixed, msg) % 8 == 0, b"kern mixed key")
    case("public key of mixed order, challenge multiple of 8", mixed, m0,
         r_enc + s_bytes((r + challenge(r_enc, mixed, m0) * a_scalar) % L),
         "The key is an ordinary key plus a point of order 8. [S]B = R + [k]A holds "
         "because [k] cancels the small part, but the key is not in the subgroup of "
         "prime order.")
    m1 = first_message(lambda msg: challenge(r_enc, mixed, msg) % 8 == 1, b"kern mixed key")
    case("public key of mixed order, challenge not multiple of 8", mixed, m1,
         r_enc + s_bytes((r + challenge(r_enc, mixed, m1) * a_scalar) % L),
         "8[S]B = 8R + 8[k]A holds, [S]B = R + [k]A does not.")

    # An honest key and R of mixed order.
    r_mixed = encode(add(mul(r, B), t8))
    m = b"kern mixed R"
    case("honest key, R of mixed order", a_enc, m,
         r_mixed + s_bytes((r + challenge(r_mixed, a_enc, m) * a_scalar) % L),
         "8[S]B = 8R + 8[k]A holds, [S]B = R + [k]A does not.")

    # Both of mixed order, with small parts that cancel.
    found = None
    for i in range(4000):
        m = b"kern mixed both " + str(i).encode()
        for t in torsion[1:]:
            r_enc = encode(add(mul(r, B), t))
            k = challenge(r_enc, mixed, m)
            if add(t, mul(k, t8)) == IDENTITY:
                found = (m, r_enc, k)
                break
        if found:
            break
    assert found is not None
    m, r_enc, k = found
    case("public key and R of mixed order, small parts cancel", mixed, m,
         r_enc + s_bytes((r + k * a_scalar) % L),
         "[S]B = R + [k]A holds exactly, with a key and a nonce point that both "
         "carry a point of small order: neither is in the subgroup of prime order.")

    # A public key written with y >= p, not of small order: nobody can sign for it.
    y = 2
    while True:
        x = recover_x(y, 0)
        if x is not None and order((x, y)) > 8:
            break
        y += 1
    assert x is not None
    case(f"public key written as y + p (y = {y}), ordinary signature bytes",
         encode((x, y), noncanonical_y=True), b"kern", honest,
         "An encoding that is not canonical, of a point nobody holds a secret for.")

    # Lengths, and a value that is not a point.
    case("public key of 31 bytes", a_enc[:31], b"kern", honest, "Truncated public key.")
    case("public key of 33 bytes", a_enc + b"\x00", b"kern", honest, "Public key with one more byte.")
    case("signature of 63 bytes", a_enc, b"kern", honest[:63], "Truncated signature.")
    case("signature of 65 bytes", a_enc, b"kern", honest + b"\x00", "Signature with one more byte.")
    assert recover_x(2, 0) is None
    case("public key that is not a point", (2).to_bytes(32, "little"), b"kern", honest,
         "No point of the curve has y = 2.")
    return cases


def is_a_key(pk: bytes) -> bool:
    """Rule 2 of the rule of Kern, alone: `pk` is the canonical encoding of
    a point of the subgroup of prime order, other than the identity. It is
    what is checked when a key is recorded, before any signature exists."""
    a = decode_strictly(pk)
    return a is not None and a != IDENTITY and mul(L, a) == IDENTITY


def build_key_cases() -> list[dict]:
    """Public keys under rule 2 alone: the ordinary key of the cases above,
    then that key plus each of the seven points of small order other than
    the identity. The seven sums are points of the curve in canonical
    encoding, and none is in the subgroup of prime order, whatever the
    order of the point that was added. Deterministic.

    A library has answered wrongly on the first of the seven: libsodium,
    before the correction published as CVE-2025-69277, took a point of
    prime order plus the point of order 2 for a point of the subgroup."""
    seed = hashlib.sha512(b"kern ed25519 edge cases").digest()[:32]
    a_point = mul(secret_scalar(seed)[0], B)
    keys = [{"name": "ordinary key", "public_key": encode(a_point).hex(),
             "comment": "A point of the subgroup of prime order: the key of the honest cases."}]
    seen: dict[int, int] = {}
    for t in torsion_points():
        n = order(t)
        if n == 1:
            continue
        seen[n] = seen.get(n, 0) + 1
        which = f", point {seen[n]}" if n > 2 else ""
        keys.append({"name": f"ordinary key plus a point of order {n}{which}",
                     "public_key": encode(add(a_point, t)).hex(),
                     "comment": f"Canonical, on the curve, of order {n} times the group order: "
                                "not in the subgroup of prime order."})
    return keys


CASES = Path(__file__).resolve().parent / "vectors" / "kern" / "ed25519_edge_cases.json"


if __name__ == "__main__":
    out = CASES
    built = build_cases()
    for c in built:
        pk, m, sig = (bytes.fromhex(c[k]) for k in ("public_key", "message", "signature"))
        c["valid"] = strict_verify(pk, m, sig)
        c["lenient"] = lenient_verify(pk, m, sig)
    keys = build_key_cases()
    for c in keys:
        c["valid"] = is_a_key(bytes.fromhex(c["public_key"]))
    document = {
        "description": "Ed25519 signatures on which implementations disagree. `valid` is the verdict of "
                       "Kern (docs/hybrid-signatures.md, section 2.5). `lenient` is the verdict of a "
                       "verifier that makes only the checks RFC 8032 requires and compares the bytes of R.",
        "generator": "tests/ed25519_reference.py",
        "cases": built,
        "public_keys_rule": "Public keys under rule 2 of section 2.5 alone, the check made when a key is "
                            "recorded: `valid` says whether the 32 bytes are the canonical encoding of a "
                            "point of the subgroup of prime order, other than the identity. Added after "
                            "the freeze of the profile, for a rule that exists: the cases above are unchanged.",
        "public_keys": keys,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}: {len(built)} cases, {sum(c['valid'] for c in built)} valid, "
          f"{sum(c['lenient'] and not c['valid'] for c in built)} accepted only by a lenient verifier; "
          f"{len(keys)} public keys, {sum(c['valid'] for c in keys)} valid",
          file=sys.stderr)
