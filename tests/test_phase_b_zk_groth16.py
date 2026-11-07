# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 5: verify_zk_claim performs a real Groth16 check on BN254.

Audit 2, point 3: the verifier used to return True for any well formed
claim. The vectors below are constructed to SATISFY the Groth16 equation

    e(A, B) == e(alpha1, beta2) * e(vk_x, gamma2) * e(C, delta2)

by choosing discrete logs for every point and solving for C, so a valid
proof verifies and every single-field tampering is rejected. No trusted
setup or circuit is involved: this tests the verifier, not a prover."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


from py_ecc import optimized_bn128 as ob

from kern.zk_claims import (
    build_zk_claim,
    check_zk_claim_shape,
    derive_verifier_key_hash,
    verifier_key_bytes,
    verify_zk_claim,
)

N = ob.curve_order


def _g1(k):
    x, y = ob.normalize(ob.multiply(ob.G1, k))
    return [int(x.n), int(y.n)]


def _g2(k):
    x, y = ob.normalize(ob.multiply(ob.G2, k))
    return [[int(x.coeffs[0]), int(x.coeffs[1])], [int(y.coeffs[0]), int(y.coeffs[1])]]


def _vectors(public_inputs):
    alpha, beta, gamma, delta = 11, 13, 17, 19
    ic_k = [23 + 2 * i for i in range(len(public_inputs) + 1)]
    r, s = 29, 31
    x_scalar = (ic_k[0] + sum(x * k for x, k in zip(public_inputs, ic_k[1:]))) % N
    t = ((r * s - alpha * beta - x_scalar * gamma) * pow(delta, -1, N)) % N
    vk = {
        "alpha1": _g1(alpha), "beta2": _g2(beta), "gamma2": _g2(gamma),
        "delta2": _g2(delta), "ic": [_g1(k) for k in ic_k],
    }
    vk_hash = derive_verifier_key_hash(verifier_key_bytes(vk))
    claim = build_zk_claim(vk_hash, list(public_inputs), _g1(r), _g2(s), _g1(t),
                           "test predicate")
    return claim, {vk_hash: vk}


@pytest.fixture(scope="module")
def valid():
    return _vectors([42, 7])


def test_valid_proof_verifies(valid):
    claim, registry = valid
    assert verify_zk_claim(claim, registry) is True


def test_tampered_public_input_is_rejected(valid):
    claim, registry = valid
    bad = dict(claim, public_inputs=[43, 7])
    assert verify_zk_claim(bad, registry) is False


def test_tampered_proof_point_is_rejected(valid):
    claim, registry = valid
    bad = dict(claim, proof=dict(claim["proof"], c=_g1(5)))
    assert verify_zk_claim(bad, registry) is False


def test_point_off_curve_is_rejected(valid):
    claim, registry = valid
    a = claim["proof"]["a"]
    bad = dict(claim, proof=dict(claim["proof"], a=[a[0], a[1] + 1]))
    assert verify_zk_claim(bad, registry) is False


def test_without_registry_nothing_is_verified(valid):
    claim, _ = valid
    assert verify_zk_claim(claim) is False
    assert verify_zk_claim(claim, {}) is False
    # The structural check alone still passes, and is named for what it is.
    assert check_zk_claim_shape(claim) is True


def test_registry_entry_must_hash_to_the_claimed_key(valid):
    claim, registry = valid
    vk = dict(next(iter(registry.values())))
    vk["alpha1"] = _g1(12)                      # another circuit's key
    assert verify_zk_claim(claim, {claim["verifier_key_hash"]: vk}) is False


def test_wrong_number_of_public_inputs_is_rejected(valid):
    claim, registry = valid
    assert verify_zk_claim(dict(claim, public_inputs=[42]), registry) is False


def test_other_proof_systems_are_not_accepted(valid):
    claim, registry = valid
    assert verify_zk_claim(dict(claim, proof_system="plonk-bn254"), registry) is False
