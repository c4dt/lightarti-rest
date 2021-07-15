"""
Tests suite
"""

from random import Random
from pathlib import Path

import pytest

from Crypto.PublicKey import RSA
from stem.descriptor.microdescriptor import Microdescriptor

from stem.descriptor.networkstatus import (
    KeyCertificate,
    NetworkStatusDocumentV3,
)
from stem.directory import Authority
from stem.exit_policy import MicroExitPolicy

from gen_fresh_dirinfo import (
    AUTHORITY_MTBF_MEASURE,
    FLAG_BAD_EXIT,
    FLAG_EXIT,
    FLAG_FAST,
    FLAG_GUARD,
    consensus_validate_signatures,
    fetch_authorities,
    fetch_certificates,
    fetch_latest_consensus,
    fetch_microdescriptors,
    fetch_vote,
    is_orport_used,
    generate_signed_consensus,
    select_routers
)

from authorities import AUTHORITIES


# Small valid consensus taken from Arti.
PATH_CONSENSUS_OK = Path("test-data")/"consensus-ok.txt"

# Same consensus with 1 invalid signature
PATH_CONSENSUS_1ERR = Path("test-data")/"consensus-1err.txt"

# Same consensus with 2 invalid signature
PATH_CONSENSUS_2ERR = Path("test-data")/"consensus-2err.txt"

PATH_CONSENSUS_CUSTOM = Path("test-data")/"consensus-custom.txt"

PATH_AUTH_CERTIFICATE = Path("test-data")/"authority_certificate"
PATH_AUTH_SIGNING_KEY = Path("test-data")/"authority_signing_key"

AUTH_CERTIFICATES = [KeyCertificate(cert) for cert in AUTHORITIES]


@pytest.fixture(scope="session")
def authorities():
    """
    Latest directory authorities data from the Tor network.
    """
    authorities = fetch_authorities()
    return authorities


@pytest.fixture(scope="session")
def consensus():
    """
    Latest consensus from the Tor network.
    """
    consensus = fetch_latest_consensus()
    return consensus


@pytest.fixture(scope="session")
def vote(authorities):
    """
    Vote of one of the directory authority measuring the MTBF of the routers.
    """
    authority = authorities[AUTHORITY_MTBF_MEASURE]
    vote = fetch_vote(authority)
    return vote


@pytest.fixture(scope="session")
def certificates(consensus):
    """
    Certificates of the directory authorities.
    """
    v3idents = [auth.v3ident for auth in consensus.directory_authorities]
    certificates = fetch_certificates(v3idents)
    return certificates


def test_fetch_consensus(consensus):
    """
    Test fetching consensus works.
    """
    assert isinstance(consensus, NetworkStatusDocumentV3)


def test_signature_validation_succeed():
    """
    Test that the signature validation succeeds when it should succeed.
    """
    with PATH_CONSENSUS_OK.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    consensus = NetworkStatusDocumentV3(consensus_raw)

    res = consensus_validate_signatures(consensus, AUTH_CERTIFICATES)

    assert res

    # Should also work if the two other signatures validates.
    with PATH_CONSENSUS_1ERR.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    consensus = NetworkStatusDocumentV3(consensus_raw)

    res = consensus_validate_signatures(consensus, AUTH_CERTIFICATES)

    assert res




def test_signature_validation_fails():
    """
    Test that the signature validation fails when it should fail.
    """
    with PATH_CONSENSUS_2ERR.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    consensus = NetworkStatusDocumentV3(consensus_raw)

    res = consensus_validate_signatures(consensus, AUTH_CERTIFICATES)

    assert not res


def test_generate_signed_consensus():
    """
    Test signature generation.
    """
    with PATH_CONSENSUS_OK.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    consensus = NetworkStatusDocumentV3(consensus_raw)

    with PATH_AUTH_SIGNING_KEY.open("rb") as signing_key_fd:
        signing_key_raw = signing_key_fd.read()

    signing_key = RSA.import_key(signing_key_raw)

    with PATH_AUTH_CERTIFICATE.open("rb") as certificate_fd:
        certificate_raw = certificate_fd.read()

    certificate = KeyCertificate(certificate_raw)

    routers = [consensus.routers[key] for key in sorted(consensus.routers.keys())]

    signed_consensus_raw = generate_signed_consensus(
        consensus,
        routers,
        signing_key,
        certificate,
        "foo",
        "127.0.0.1",
        "127.0.0.1",
        80,
        443,
        "bar",
        7
    )

    signed_consensus = NetworkStatusDocumentV3(signed_consensus_raw)

    assert consensus_validate_signatures(signed_consensus, [certificate])

    routers_b = [
        signed_consensus.routers[key] for key in sorted(signed_consensus.routers.keys())
    ]

    assert len(routers) == len(routers_b)

    for router_a, router_b in zip(routers, routers_b):
        assert router_a.microdescriptor_digest == router_b.microdescriptor_digest



def test_fetch_authorities(authorities):
    """
    Test fetching directory authorities information.
    """
    assert len(authorities) > 5

    for auth in authorities.values():
        assert isinstance(auth, Authority)



def test_fetch_certificates(certificates):
    """
    Test fetching certificates of directory authorities works.
    """
    assert len(certificates) > 5

    for cert in certificates:
        assert isinstance(cert, KeyCertificate)



def test_fetch_microdescriptors(consensus):
    """
    Test fetching microdescriptors works.
    """
    n_routers = 30
    rng = Random(0)

    fingerprints = rng.choices(list(consensus.routers.keys()), k=n_routers)

    routers = [consensus.routers[key] for key in fingerprints]

    microdescriptors = fetch_microdescriptors(routers)

    assert len(microdescriptors) == n_routers

    for md in microdescriptors:
        assert isinstance(md, Microdescriptor)

    digests_a = {router.microdescriptor_digest for router in routers}
    digests_b = {md.digest() for md in microdescriptors}

    assert digests_a == digests_b



def test_select_routers(consensus, vote):
    """
    Test that router selection works correctly.
    """
    n_routers = 30

    routers = select_routers(consensus, vote, n_routers)

    assert len(routers) == n_routers

    # Ensure the routers are selected correctly.
    for router in routers:
        flags = set(router.flags)
        assert FLAG_BAD_EXIT not in flags
        assert FLAG_FAST in flags

    # Ensures the routers are sorted.
    routers_b = sorted(routers, key=lambda r: int(r.fingerprint, 16))

    for ra, rb in zip(routers, routers_b):
        assert ra.get_bytes() == rb.get_bytes()


def test_generate_signed_consensus_from_real_data(consensus, vote):
    """
    """

    with PATH_AUTH_SIGNING_KEY.open("rb") as signing_key_fd:
        signing_key_raw = signing_key_fd.read()

    signing_key = RSA.import_key(signing_key_raw)

    with PATH_AUTH_CERTIFICATE.open("rb") as certificate_fd:
        certificate_raw = certificate_fd.read()

    certificate = KeyCertificate(certificate_raw)

    routers = select_routers(consensus, vote, 120)

    signed_consensus_raw = generate_signed_consensus(
        consensus,
        routers,
        signing_key,
        certificate,
        "foo",
        "127.0.0.1",
        "127.0.0.1",
        80,
        443,
        "bar",
        7
    )

    signed_consensus = NetworkStatusDocumentV3(signed_consensus_raw)

    assert consensus_validate_signatures(signed_consensus, [certificate])

    routers = [
        signed_consensus.routers[key] for key in sorted(signed_consensus.routers.keys())
    ]

    for router in routers:
        if FLAG_GUARD in router.flags:
            if not is_orport_used(router, 443):
                print(router.get_bytes().decode())

        if FLAG_EXIT in router.flags:
            assert FLAG_GUARD not in router.flags


