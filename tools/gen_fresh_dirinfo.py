#!/usr/bin/env python3

# Copyright 2021 Laurent Girod (EPFL SPRING Lab)

"""
Script to produce data to pass to lightarti-rest.
"""

import logging
import re
import sys

from argparse import (
    ArgumentParser,
    Namespace,
)
from base64 import (
    b64decode,
    b64encode,
)
from datetime import timedelta
from hashlib import (
    sha1,
    sha256,
)
from heapq import nlargest
from math import ceil, floor
from itertools import zip_longest
from os import environ
from pathlib import Path
from subprocess import (
    Popen,
    PIPE,
    TimeoutExpired,
)
from typing import (
    Dict,
    List,
    Optional,
    Tuple,
)

from Crypto.PublicKey import RSA

from stem.descriptor import (
    DocumentHandler,
    DigestHash,
    DigestEncoding,
)
from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.networkstatus import (
    DocumentSignature,
    KeyCertificate,
    NetworkStatusDocumentV3,
)
from stem.descriptor.remote import (
    DescriptorDownloader,
    MAX_MICRODESCRIPTOR_HASHES,
)
from stem.descriptor.router_status_entry import RouterStatusEntryMicroV3
from stem.directory import Authority
from stem.exit_policy import MicroExitPolicy


# Environment variable from which to retrieve the password to encrypt the identity key of the
# custom directory authority.
DIR_AUTH_PASSWORD_ENV = "DIR_AUTH_PASSWORD"

# Time format used in the consensus.
CONSENSUS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Router flags in which we are interested.
FLAG_BAD_EXIT = "BadExit"
FLAG_EXIT = "Exit"
FLAG_FAST = "Fast"
FLAG_GUARD = "Guard"
FLAG_STABLE = "Stable"

# As of July 2021, mean time before failure (MTBF) is not published in the consensus, but the
# two directory authorities, moria1 and maatuska are publishing these statistics in their vote.
AUTHORITY_MTBF_MEASURE = "moria1"

# Format of an authority entry in the consensus (with a dummy vote digest).
AUTHORITY_FMT = """dir-source {name} {fingerprint} {hostname} {ip_address} {dirport} {orport}
contact {contact}
vote-digest 0000000000000000000000000000000000000000
"""

# Header of a consensus (with many values already set).
CONSENSUS_HEADER_FMT = """network-status-version 3 microdesc
vote-status consensus
consensus-method 30
valid-after {valid_after}
fresh-until {fresh_until}
valid-until {valid_until}
voting-delay 300 300
client-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.3.5.15,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.4.9,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.5.9,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc,0.4.6.4-rc,0.4.6.5
server-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.3.5.15,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.4.9,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.5.9,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc,0.4.6.4-rc,0.4.6.5
known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
required-client-protocols Cons=2 Desc=2 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
params CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1 DoSConnectionEnabled=1 DoSConnectionMaxConcurrentCount=50 DoSRefuseSingleHopClientRendezvous=1 ExtendByEd25519ID=1 KISTSchedRunInterval=2 NumDirectoryGuards=3 NumEntryGuards=1 NumNTorsPerTAP=100 UseOptimisticData=1 bwauthpid=1 cbttestfreq=10 hs_service_max_rdv_failures=1 hsdir_spread_store=4 pb_disablepct=0 sendme_emit_min_version=1 usecreatefast=0
shared-rand-previous-value 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
shared-rand-current-value 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
"""

# Footer of the consensus included in the signature's hash.
# For now, weight are kept to similar values found in the consensus.
CONSENSUS_FOOTER_IN_SIGNATURE = b"""directory-footer
bandwidth-weights Wbd=0 Wbe=0 Wbg=4273 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5727 Wgm=5727 Wmb=10000 Wmd=0 Wme=0 Wmg=4273 Wmm=10000
directory-signature """

# Regex to parse the raw base 64 content of a signature.
SIGNATURE_RE = re.compile("-+BEGIN SIGNATURE-+\n([^-]+)\n-+END SIGNATURE-+")

# Regex to parse the raw base 64 content of a RSA public key.
PUBLIC_KEY_RE = re.compile("-+BEGIN RSA PUBLIC KEY-+\n([^-]+)\n-+END RSA PUBLIC KEY-+")

# Regex to parse a raw hash packed as a PKCS#1 1.5 format.
PKCS1_15_HASH_RE = re.compile(b"\x00\x01\xff+\x00(.+)$", re.DOTALL)

# Regex to find the remove some flags from a relay.
BAD_EXIT_FLAG_RE = re.compile(b"(s.+)BadExit (.+)", re.MULTILINE)
EXIT_FLAG_RE = re.compile(b"(s.*) Exit(.+)", re.MULTILINE)
GUARD_FLAG_RE = re.compile(b"(s.+)Guard (.+)", re.MULTILINE)

# Maximum ratio of churned routers in a customized consensus.
CHURN_THRESHOLD_RATIO = 1/6


Address = Tuple[str, int, bool]


class InvalidConsensus(Exception):
    """
    The consensus is invalid.
    """


class InvalidVote(Exception):
    """
    The vote is invalid.
    """


class TorCertGenFailed(Exception):
    """
    The command tor-gencert failed.
    """


class ChurnAboveThreshold(Exception):
    """
    The number of churned routers is above the threshold.
    """


def setup_logger() -> logging.Logger:
    """
    Setup the logger.

    :return: a logger adapted for our usage
    """
    logger = logging.getLogger("arti-data-gen")
    logger.setLevel(logging.INFO)

    #handler = logging.FileHandler("arti-data-gen.log")
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s:%(name)s:%(levelname)s:%(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# Logger to use in this program.
LOGGER = setup_logger()


def is_orport_used(router: RouterStatusEntryMicroV3, port: int) -> bool:
    """
    Check if a port is used as an OR port by a router on its IPv4 address.

    :param router: router entry in the consensus
    :param port: port we want to check
    :return: True if the port is used, False otherwise
    """
    # This field correspond to the OR port specified in the "router" line of a router's description.
    # Per Tor's spec it is always used for an IPv4 address.
    # (Tor directory protocol, version 3, 2.1.1.)
    return router.or_port == port


def is_address_port_changed(
        addresses_ports_origin: List[Address],
        addresses_ports_new: List[Address]
    ) -> bool:
    """
    Check if the address or the port changed between the addresses of two OR routers.

    :param addresses_ports_origin: list of addresses and ports in the original router description
    :param addresses_ports_new: list of addresses and ports in an updated router description
    :return: True if at least one of the original address or port has changed, False otherwise
    """
    new_addresses = {addr[0] for addr in addresses_ports_new}
    new_ports = {addr[1] for addr in addresses_ports_new}
    for address_origin, port_origin, _ in addresses_ports_origin:
        if address_origin not in new_addresses:
            return True
        if port_origin not in new_ports:
            return True

    return False


def terminate_process(process: Popen) -> None:
    """
    Terminate a process in a clean way.

    :param process: process to terminate
    """
    process.terminate()
    try:
        process.communicate(timeout=3)
    except TimeoutExpired:
        process.kill()


def call_tor_gencert(
        password: bytes,
        create_new_identity: bool,
        reuse_signing_key: bool,
        identity_key_file: Path,
        signing_key_file: str,
        certificate_file: str,
        lifetime_in_months: int,
    ) -> None:
    """
    Call the tor-gencert command to generate key pairs and certificate.

    :param password: the password to encrypt the identity key
    :param create_new_identity: create a new identity key
    :param reuse_signing_key: reuse an existing signing key
    :param identity_key_file: file where to read or write the identity key
    :param signing_key_file: file where to read or write the signing key
    :param certificate_file: file where to write the certificate
    :param lifetime_in_months: lifetime of the certificate in months
    :raises TorCertGenFailed: The tor-gencert command failed.
    """

    args = [
        "tor-gencert",
        "-i", str(identity_key_file),
        "-s", str(signing_key_file),
        "-c", str(certificate_file),
        "-m", f"{lifetime_in_months}",
        "--passphrase-fd", "0"
    ]

    if create_new_identity:
        args.append("--create-identity-key")

    if reuse_signing_key:
        args.append("--reuse")

    process = Popen(args, stdin=PIPE)
    try:
        process.communicate(password, timeout=10)
    except TimeoutExpired:
        terminate_process(process)
        raise TorCertGenFailed()

    ret = process.poll()

    if ret is None:
        terminate_process(process)
        ret = process.poll()

    if ret != 0:
        raise TorCertGenFailed()


def fetch_authorities() -> Dict[str, Authority]:
    """
    Retrieve voting directory authorities.

    :return: dictionary matching the name of the authorities to their object
    """
    authorities = Authority.from_cache()
    signing_authorities = {name: auth for name, auth in authorities.items() if auth.v3ident}
    return signing_authorities


def fetch_vote(
        authority: Authority
    ) -> NetworkStatusDocumentV3:
    """
    Fetch the latest vote from the authority.

    :param authority: directory authority from which we want to retrieve the vote.
    :raises ValueError: Did not retrieve the expected vote format.
    :return: the vote of the directory authority
    """
    # pylint: disable=no-member

    downloader = DescriptorDownloader()

    vote = downloader.get_vote(
        authority,
        document_handler=DocumentHandler.DOCUMENT,
        timeout=10
    ).run()[0]

    if not isinstance(vote, NetworkStatusDocumentV3):
        raise ValueError(f"Unexpected vote format {type(vote)}")

    return vote


def fetch_latest_consensus() -> NetworkStatusDocumentV3:
    """
    Fetch the latest consensus from the network.

    :raises ValueError: Did not retrieve the expected consensus format.
    :return: the fresh consensus parsed by stem
    """
    # pylint: disable=no-member

    downloader = DescriptorDownloader()

    consensus = downloader.get_consensus(
        document_handler=DocumentHandler.DOCUMENT,
        microdescriptor=True,
    ).run()[0]

    if not isinstance(consensus, NetworkStatusDocumentV3):
        raise ValueError(f"Unexpected consensus format {type(consensus)}")

    return consensus


def fetch_microdescriptors(
        routers: List[RouterStatusEntryMicroV3]
    ) -> List[Microdescriptor]:
    """
    Fetch the microdescriptors described in the entries.

    :param routers: list of routers status found in the consensus for which we want the
        microdescriptors
    :raises ValueError: Did not retrieve the expected microdescriptor format.
    :return: a list of microdescriptors
    """
    downloader = DescriptorDownloader()
    microdescriptors: List[Microdescriptor] = list()
    buckets = [
        iter(r.microdescriptor_digest for r in routers)
    ] * MAX_MICRODESCRIPTOR_HASHES
    for bucket in zip_longest(*buckets):
        digests = [h for h in bucket if h is not None]
        microdescriptors_bucket = downloader.get_microdescriptors(
            hashes=digests,
            validate=True
        ).run()

        digests_set = set(digests)
        for microdescriptor in microdescriptors_bucket:
            if not isinstance(microdescriptor, Microdescriptor):
                raise ValueError(f"Unexpected microdescriptor format {type(microdescriptor)}")

            if microdescriptor.digest() not in digests_set:
                raise ValueError("Unexpected microdescriptor retrieved.")

        microdescriptors += microdescriptors_bucket

    return microdescriptors


def fetch_certificates(v3idents: List[str]) -> List[KeyCertificate]:
    """
    Fetch current certificates of the directory authorities from the network.

    :param v3idents: identities of the directory authorities in v3 format
    :raises ValueError: Did not retrieve the expected certificate format.
    :return: a list of certificates
    """
    downloader = DescriptorDownloader()
    certificates = downloader.get_key_certificates(v3idents, validate=True).run()

    for certificate in certificates:
        if not isinstance(certificate, KeyCertificate):
            raise ValueError(f"Unexpected certificate format {type(certificate)}")

    return certificates


def retrieve_hash_from_signature(
        certificate: KeyCertificate,
        signature: DocumentSignature
    ) -> Optional[bytes]:
    """
    As Tor does not do the full PKCS#1 1.5 signature scheme, and Stem's validation does not seems
    to work in the current version, we implemented our own way to retrieve the hash from a
    signature.

    :param certificate: certificate to use to compute the hash of the document
    :param signature: signature to validate
    :return: the hash retrieved from the signature, or None if we failed to retrieve the hash
    """
    public_key = RSA.import_key(certificate.signing_key)
    sign_match = SIGNATURE_RE.search(signature.signature)
    if sign_match is None:
        return None

    sign_b = b64decode(sign_match.group(1))
    sign_i = int.from_bytes(sign_b, "big")

    # We need to do a raw RSA in this case.
    # pylint: disable=protected-access
    key_size = public_key.size_in_bytes()
    retrieved_hash = public_key._encrypt(sign_i).to_bytes(key_size, "big")
    retrieved_hash_match = PKCS1_15_HASH_RE.match(retrieved_hash)
    if retrieved_hash_match is None:
        return None

    retrieved_hash = retrieved_hash_match.group(1)

    return retrieved_hash


def consensus_validate_signatures(
        consensus: NetworkStatusDocumentV3,
        key_certificates: List[KeyCertificate]
    ) -> bool:
    """
    Validate the signature of a consensus.

    :param consensus: Consensus to validate.
    :param key_certificates: list of certificates against the signatures of certificate needs to be
        validated.
    :return: True if the certificate is valid, False otherwise
    """
    # pylint: disable=no-member
    consensus_digest: bytes = consensus.digest(DigestHash.SHA256, DigestEncoding.RAW).digest()

    num_valid = 0

    for certificate in key_certificates:
        # Look up for the signature allegedly made with this certificate.
        fingerprint = certificate.fingerprint
        signature = next(
            filter(
                lambda sig, fingerprint=fingerprint:
                sig.identity == fingerprint, consensus.signatures
            ),
            None
        )
        if signature is None:
            continue

        retrieved_hash = retrieve_hash_from_signature(certificate, signature)

        if retrieved_hash is not None and retrieved_hash == consensus_digest:
            num_valid += 1

    return num_valid > (len(consensus.signatures) * 0.5)


def extract_mtbf(router: Optional[RouterStatusEntryMicroV3]) -> int:
    """
    Extract the mean time before failure (MTBF) from the entries parsed by Stem.

    :param router: router from which we want the measured MTBF
    :return: the MTBF of the router or 0 it it can not be retrieved
    """
    if not router:
        return 0

    # We need to access to the entries parsed by Stem.
    # pylint: disable=protected-access
    stats_line = router._entries.get("stats", None)
    if not stats_line or not stats_line[0] or not stats_line[0][0]:
        return 0

    raw_stats: Dict[str, str] = dict(tuple(s.split("=")) for s in stats_line[0][0].split(" "))
    return int(raw_stats.get("mtbf", 0))


def select_potential_routers(
        consensus: NetworkStatusDocumentV3,
        mtbf_vote: NetworkStatusDocumentV3
    ) -> Tuple[
        List[RouterStatusEntryMicroV3],
        List[RouterStatusEntryMicroV3],
        List[RouterStatusEntryMicroV3]
    ]:
    """
    Select the potential routers to act as guards, middle relays and exits.

    :param consensus: original consensus from which we select routers
    :param mtbf_vote: vote of an authority publishing MTBF values
    :return: a tuple containing potential guards, middle and exit routers
    """
    potential_guards: List[RouterStatusEntryMicroV3] = list()
    potential_middles: List[RouterStatusEntryMicroV3] = list()
    potential_exits: List[RouterStatusEntryMicroV3] = list()

    for router in consensus.routers.values():
        flags = set(router.flags)

        # We only consider routers which are stable and fast.
        if FLAG_STABLE in flags and FLAG_FAST in flags:

            # Guards need to be reachable on HTTPS port to bypass strict firewalls.
            if FLAG_GUARD in flags and is_orport_used(router, 443):
                potential_guards.append(router)

            # Exit routers need be able to connect to HTTPS port.
            if FLAG_EXIT in flags and FLAG_BAD_EXIT not in flags:
                vote_entry = mtbf_vote.routers.get(router.fingerprint, None)
                if vote_entry:
                    exit_policy: MicroExitPolicy = vote_entry.exit_policy
                    if exit_policy.can_exit_to(port=443):
                        potential_exits.append(router)

            # All other nodes can be potential middle nodes.
            potential_middles.append(router)

    return potential_guards, potential_middles, potential_exits


def select_routers(
        consensus: NetworkStatusDocumentV3,
        mtbf_vote: NetworkStatusDocumentV3,
        number_routers: int,
    ) -> List[RouterStatusEntryMicroV3]:
    """
    Select a subset of routers in the consensus.

    :param consensus: the consensus containing routers descriptions
    :param mtbf_vote: vote of an authority publishing MTBF values
    :param n_routers: the final number of routers that we would like
    :raises ValueError: One of the parameter given in argument has an invalid value.
    :return: list of router entries matching the criteria of the selection
    """

    if number_routers > len(consensus.routers):
        raise ValueError("Not enough routers in consensus")

    number_guards = ceil(0.33 * number_routers)
    number_exits = number_guards
    number_middles = number_routers - number_guards - number_exits

    (
        potential_guards,
        potential_middles,
        potential_exits
    ) = select_potential_routers(consensus, mtbf_vote)

    if number_guards > len(potential_guards):
        LOGGER.warning(
            "Insufficient number of guard routers in the consensus (%d routers present).",
            len(potential_guards)
        )

    if number_exits > len(potential_exits):
        LOGGER.warning(
            "Insufficient number of exit routers in the consensus (%d routers present).",
            len(potential_exits)
        )

    # We cache the MTBF values to avoid having to parse the line multiple times.
    mtbf_cache = {
        router.fingerprint: extract_mtbf(mtbf_vote.routers.get(router.fingerprint, None))
        for router in potential_guards + potential_middles + potential_exits
    }

    # We select the most stable exit nodes.
    exits = nlargest(
        number_exits,
        potential_exits,
        key=lambda r: mtbf_cache.get(r.fingerprint, 0)
    )

    selected_set = {router.fingerprint for router in exits}

    # We select the most stable guard nodes we haven't yet selected.
    guards = nlargest(
        number_guards,
        potential_guards,
        key=lambda r: mtbf_cache.get(r.fingerprint, 0) if r.fingerprint not in selected_set else 0
    )

    for router in guards:
        selected_set.add(router.fingerprint)

    # We select the most stable routers we haven't yet selected as middle nodes.
    middles = nlargest(
        number_middles,
        potential_middles,
        key=lambda r: mtbf_cache.get(r.fingerprint, 0) if r.fingerprint not in selected_set else 0
    )

    # We remove exit flags from routers not selected as potential exit relay.
    for router in guards + middles:
        if FLAG_EXIT in router.flags:
            router.flags.remove(FLAG_EXIT)
        if FLAG_BAD_EXIT in router.flags:
            router.flags.remove(FLAG_BAD_EXIT)

    # We do not want guards reachable through non-HTTPS ports due to strict firewall.
    for router in middles + exits:
        if FLAG_GUARD in router.flags:
            router.flags.remove(FLAG_GUARD)

    routers = sorted(guards + middles + exits, key=lambda r: int(r.fingerprint, 16))

    return routers


def sign_consensus(
        consensus_unsigned: bytes,
        authority_signing_key: RSA.RsaKey,
        authority_certificate: KeyCertificate,
    ) -> bytes:
    """
    Sign a raw unsigned consensus.

    :param consensus_unsigned: raw consensus that need to be signed
    :param authority_signing_key: signing key of the authority to sign the consensus
    :param authority_certificate: certificate of the authority used to generate the signature's
        metadata
    :return: raw signed consensus
    """

    # Compute the digest of the signing key.
    public_key_match = PUBLIC_KEY_RE.search(authority_certificate.signing_key)
    if public_key_match is None:
        raise ValueError("A certificate contains an invalid public key.")

    public_key_b64 = public_key_match.group(1)
    key_b = b64decode(public_key_b64)
    signing_key_digest = sha1(key_b).hexdigest().upper()

    consensus_digest_raw = sha256(consensus_unsigned).digest()

    signature_size = authority_signing_key.size_in_bytes()
    padding_len = signature_size - len(consensus_digest_raw)
    consensus_digest = (
        b"\x00\x01" +
        (b"\xff" * (padding_len - 3)) +
        b"\x00" +
        consensus_digest_raw
    )

    consensus_digest_i = int.from_bytes(consensus_digest, "big")

    # We need to do a raw RSA in this case.
    # pylint: disable=protected-access
    signature_b = authority_signing_key._decrypt(consensus_digest_i).to_bytes(signature_size)

    signature_b64 = b64encode(signature_b).decode("ascii")
    signature_pem = (
        "-----BEGIN SIGNATURE-----\n" +
        re.sub("(.{64})", "\\1\n", signature_b64, 0, re.DOTALL) +
        "\n-----END SIGNATURE-----\n"
    )

    auth_fingerprint = authority_certificate.fingerprint
    signature = (
        f"sha256 {auth_fingerprint} {signing_key_digest}\n{signature_pem}"
        .encode("ascii")
    )

    return consensus_unsigned + signature


def generate_signed_consensus(
        consensus: NetworkStatusDocumentV3,
        routers: List[RouterStatusEntryMicroV3],
        authority_signing_key: RSA.RsaKey,
        authority_certificate: KeyCertificate,
        authority_name: str,
        authority_hostname: str,
        authority_ip_address: str,
        authority_dirport: int,
        authority_orport: int,
        authority_contact: str,
        consensus_validity_days: int
    ) -> bytes:
    """
    Generate a consensus with a custom set of routers, signed by a custom authority.

    :param consensus: original consensus
    :param routers: list of routers selected from the original consensus
    :param authority_signing_key: RSA key of the authority that need to sign the consensus
    :param authority_certificate: certificate of the authority that need to sign the consensus
    :param authority_name: name of the authority
    :param authority_addresses: IP addresses of the authority
    :param authority_ports: OR port and DIR port of the authority
    :param authority_contact: contact info of the authority
    :param consensus_validity_days: lifetime of the consensus in days
    :return: signed consensus with a subset of the routers
    """

    # Prepare the header of the consensus with corrected lifetime.
    valid_after = consensus.valid_after
    fresh_until = valid_after + timedelta(days=consensus_validity_days)
    valid_until = fresh_until + timedelta(days=consensus_validity_days)
    header = CONSENSUS_HEADER_FMT.format(
        valid_after=valid_after.strftime(CONSENSUS_TIME_FORMAT),
        fresh_until=fresh_until.strftime(CONSENSUS_TIME_FORMAT),
        valid_until=valid_until.strftime(CONSENSUS_TIME_FORMAT)
    ).encode("ascii")

    # Prepare our authority entry.
    authority = AUTHORITY_FMT.format(
        name=authority_name,
        fingerprint=authority_certificate.fingerprint,
        hostname=authority_hostname,
        ip_address=authority_ip_address,
        dirport=authority_dirport,
        orport=authority_orport,
        contact=authority_contact
    ).encode("ascii")

    # prepare router entries
    # remove unwanted flags
    routers_b = b""
    for router in routers:
        router_b: bytes = router.get_bytes()

        if FLAG_GUARD not in router.flags:
            router_b = GUARD_FLAG_RE.sub(b"\\g<1>\\g<2>", router_b)

        if FLAG_BAD_EXIT not in router.flags:
            router_b = BAD_EXIT_FLAG_RE.sub(b"\\g<1>\\g<2>", router_b)

        if FLAG_EXIT not in router.flags:
            router_b = EXIT_FLAG_RE.sub(b"\\g<1>\\g<2>", router_b)

        routers_b += router_b

    # Tor do not follow the PKCS#1 v1.5 signature scheme strictly,
    # so we can not rely on a library to do it.
    consensus_unsigned = (
        header +
        authority +
        routers_b +
        CONSENSUS_FOOTER_IN_SIGNATURE
    )

    consensus_signed = sign_consensus(
        consensus_unsigned,
        authority_signing_key,
        authority_certificate
    )

    return consensus_signed


def generate_microdescriptors(microdescriptors: List[Microdescriptor]) -> bytes:
    """
    Generate microdescriptors document.

    :param microdescriptors: list of microdescriptors that need to be present in the file
    :return: bytes representation of the microdescriptors
    """
    return b"".join(m.get_bytes() for m in microdescriptors)


def compute_churn(
        consensus_customized: NetworkStatusDocumentV3,
        consensus_latest: NetworkStatusDocumentV3
    ) -> List[str]:
    """
    Compute the churn between a customized consensus produced by this script and a newer consensus.

    :param consensus_customized: customized consensus produced with this script
    :param consensus_latest: a newer consensus to compare the churn
    :return: list of fingerprints of routers no longer working
    """
    churn = list()
    for fingerprint, router in consensus_customized.routers.items():
        if fingerprint not in consensus_latest.routers:
            churn.append(router.fingerprint)
            continue

        cons_router: RouterStatusEntryMicroV3 = consensus_latest.routers[fingerprint]

        if is_address_port_changed(router.or_addresses, cons_router.or_addresses):
            churn.append(router.fingerprint)
            continue

        if (
                FLAG_EXIT in router.flags and
                (FLAG_EXIT not in cons_router.flags or FLAG_BAD_EXIT in cons_router.flags)
            ):
            churn.append(router.fingerprint)
            continue

    return churn


def validate_churn_threshold(
        churn: List[str],
        consensus_customized: NetworkStatusDocumentV3,
    ) -> None:
    """
    Validate that a generated churn contains a number of routers below a threshold.

    :param churn: current churn
    :param consensus_customized: customized consensus generated with this script
    :raises: ChurnAboveThreshold if there are too many churned relays.
    """
    threshold = floor(len(consensus_customized.routers) * CHURN_THRESHOLD_RATIO)
    if len(churn) > threshold:
        raise ChurnAboveThreshold("There are too many churned routers. "
            "Please regenerate the customized consensus.")


def generate_certificate(
        authority_identity_key_path: Path,
        authority_signing_key_path: Path,
        authority_certificate_path: Path,
        authority_v3ident_path: Path,
        authority_name: Path,
        certificate_validity_months: int
    ) -> None:
    """
    Generate a certificate for a custom authority.

    :param:
    """
    password = environ.get(DIR_AUTH_PASSWORD_ENV, None)
    if password is None:
        raise Exception(f"No password provided as environment variable {DIR_AUTH_PASSWORD_ENV}.")

    create_new_identity = not authority_identity_key_path.exists()
    reuse_signing_key = not create_new_identity and authority_signing_key_path.exists()

    call_tor_gencert(
        password.encode("utf-8"),
        create_new_identity,
        reuse_signing_key,
        authority_identity_key_path,
        authority_signing_key_path,
        authority_certificate_path,
        certificate_validity_months,
    )

    authority_certificate_raw = authority_certificate_path.read_bytes()
    authority_certificate = KeyCertificate(authority_certificate_raw)

    v3ident = f"{authority_name} {authority_certificate.fingerprint}".encode("ascii")

    authority_v3ident_path.write_bytes(v3ident)


def generate_customized_consensus(
        authority_signing_key_path: Path,
        authority_certificate_path: Path,
        consensus_path: Path,
        microdescriptors_path: Path,
        number_routers: int,
        authority_name: str,
        authority_hostname: str,
        authority_ip_address: str,
        authority_dirport: int,
        authority_orport: int,
        authority_contact: str,
        consensus_validity_days: int
    ) -> None:
    """
    Generate a customized consensus from data retrieved from the Tor network authorities.

    :param authority_signing_key_path:
    """

    # Read the relevant input files related to the authority.

    authority_signing_key_raw = authority_signing_key_path.read_bytes()

    authority_signing_key = RSA.import_key(authority_signing_key_raw)

    authority_certificate_raw = authority_certificate_path.read_bytes()

    authority_certificate = KeyCertificate(authority_certificate_raw)

    consensus_original = fetch_latest_consensus()

    v3idents = [auth.v3ident for auth in consensus_original.directory_authorities]
    key_certificates = fetch_certificates(v3idents)

    # The validation provided by Stem does not works for microdescriptor flavored consensus with
    # the tested version (1.8.0).
    if not consensus_validate_signatures(consensus_original, key_certificates):
        raise InvalidConsensus("Validation of the consensus' signature failed.")

    authorities = fetch_authorities()
    auth_mtbf = authorities[AUTHORITY_MTBF_MEASURE]
    vote_mtbf = fetch_vote(auth_mtbf)

    key_cert_mtbf = list(filter(lambda c: c.fingerprint == auth_mtbf.v3ident, key_certificates))

    try:
        vote_mtbf.validate_signatures(key_cert_mtbf)
    except ValueError as err:
        raise InvalidVote(str(err))

    routers = select_routers(
        consensus_original,
        vote_mtbf,
        number_routers,
    )

    consensus = generate_signed_consensus(
        consensus_original,
        routers,
        authority_signing_key,
        authority_certificate,
        authority_name,
        authority_hostname,
        authority_ip_address,
        authority_dirport,
        authority_orport,
        authority_contact,
        consensus_validity_days
    )

    our_consensus = NetworkStatusDocumentV3(consensus)
    if not consensus_validate_signatures(our_consensus, [authority_certificate]):
        raise InvalidConsensus("generated concensus has an invalid signature.")

    microdescriptors = fetch_microdescriptors(routers)

    microdescriptors_raw = generate_microdescriptors(microdescriptors)

    consensus_path.write_bytes(consensus)

    microdescriptors_path.write_bytes(microdescriptors_raw)


def generate_churninfo(
        consensus_path: Path,
        churn_path: Path,
        consensus_latest: NetworkStatusDocumentV3
    ) -> None:
    """
    Generate a churn file from a customized consensus and the latest consensus retrieved from the
    Tor network authorities.

    :param consensus_path: path to the customized consensus
    :param churn_path: path to the file to contain the churn information
    """
    consensus_customized = NetworkStatusDocumentV3(consensus_path.read_bytes())

    churn_fingerprints = compute_churn(consensus_customized, consensus_latest)

    churn = ("\n".join(churn_fingerprints) + "\n").encode("ascii")

    churn_path.write_bytes(churn)


def generate_certificate_cb(namespace: Namespace) -> None:
    """
    Generate a certificate for a custom authority.

    :param namespace: namespace containing parsed arguments.
    """
    authority_identity_key_path: Path = namespace.authority_identity_key
    authority_signing_key_path: Path = namespace.authority_signing_key
    authority_certificate_path: Path = namespace.authority_certificate
    authority_v3ident_path: Path = namespace.authority_v3ident
    authority_name: Path = namespace.authority_name
    certificate_validity_months: int = namespace.certificate_validity_months

    generate_certificate(
        authority_identity_key_path,
        authority_signing_key_path,
        authority_certificate_path,
        authority_v3ident_path,
        authority_name,
        certificate_validity_months
    )


def generate_customized_consensus_cb(namespace: Namespace) -> None:
    """
    Generate a customized consensus from data retrieved from the Tor network authorities.

    :param namespace: namespace containing parsed arguments.
    """
    authority_signing_key_path: Path = namespace.authority_signing_key
    authority_certificate_path: Path = namespace.authority_certificate
    consensus_path: Path = namespace.consensus
    microdescriptors_path: Path = namespace.microdescriptors
    number_routers: int = namespace.number_routers
    authority_name: str = namespace.authority_name
    authority_hostname: str = namespace.authority_hostname
    authority_ip_address: str = namespace.authority_ip_address
    authority_dirport: int = namespace.authority_dirport
    authority_orport: int = namespace.authority_orport
    authority_contact: str = namespace.authority_contact
    consensus_validity_days: int = namespace.consensus_validity_days

    generate_customized_consensus(
        authority_signing_key_path,
        authority_certificate_path,
        consensus_path,
        microdescriptors_path,
        number_routers,
        authority_name,
        authority_hostname,
        authority_ip_address,
        authority_dirport,
        authority_orport,
        authority_contact,
        consensus_validity_days,
    )


def generate_churninfo_cb(namespace: Namespace) -> None:
    """
    Generate a churn file from a customized consensus and the latest consensus retrieved from the
    Tor network authorities.

    :param namespace: namespace containing parsed arguments.
    """
    consensus_path: Path = namespace.consensus
    churn_path: Path = namespace.churn

    consensus_latest = fetch_latest_consensus()

    v3idents = [auth.v3ident for auth in consensus_latest.directory_authorities]
    key_certificates = fetch_certificates(v3idents)

    if not consensus_validate_signatures(consensus_latest, key_certificates):
        raise InvalidConsensus("Validation of the consensus' signature failed.")

    generate_churninfo(consensus_path, churn_path, consensus_latest)


def main(program: str, arguments: List[str]) -> None:
    """
    Entrypoint of the program. Parse the arguments, and call the correct function.

    :param program: name of the script.
    :param arguments: arguments passed to the program.
    """
    parser = ArgumentParser(prog=program)
    subparsers = parser.add_subparsers(help="Command")

    parser_certificate = subparsers.add_parser(
        "generate-certificate", help="Generate the certificate of a custom authority."
    )

    parser_dirinfo = subparsers.add_parser(
        "generate-dirinfo", help="Generate customized directory information."
    )

    parser_churn = subparsers.add_parser(
        "compute-churn", help="Compute current churn in customized directory information."
    )

    parser_certificate.add_argument(
        "--authority-identity-key",
        help="Signing key of the directory authority to sign the consensus.",
        type=Path,
        default="authority_identity_key"
    )
    parser_certificate.add_argument(
        "--authority-signing-key",
        help="Signing key of the directory authority to sign the consensus.",
        type=Path,
        default="authority_signing_key"
    )
    parser_certificate.add_argument(
        "--authority-certificate",
        help="Certificate of the directory authority used to verify the consensus.",
        type=Path,
        default="certificate.txt"
    )
    parser_certificate.add_argument(
        "--authority-v3ident",
        help="File containing nickname and v3ident of the authority.",
        type=Path,
        default="authority.txt"
    )
    parser_certificate.add_argument(
        "--authority-name",
        help="Name of the directory authority.",
        type=str,
        default="spring"
    )
    parser_certificate.add_argument(
        "-m",
        "--certificate-validity-months",
        help="Number of months that the certificate should be valid.",
        type=int,
        default=12
    )

    parser_certificate.set_defaults(callback=generate_certificate_cb)

    parser_dirinfo.add_argument(
        "--authority-signing-key",
        help="Signing key of the directory authority to sign the consensus.",
        type=Path,
        default="authority_signing_key"
    )
    parser_dirinfo.add_argument(
        "--authority-certificate",
        help="Certificate of the directory authority used to verify the consensus.",
        type=Path,
        default="certificate.txt"
    )
    parser_dirinfo.add_argument(
        "--authority-name",
        help="Name of the directory authority.",
        type=str,
        default="spring"
    )
    parser_dirinfo.add_argument(
        "--authority-hostname",
        help="Hostname of the directory authority.",
        type=str,
        default="127.0.0.1"
    )
    parser_dirinfo.add_argument(
        "--authority-ip-address",
        help="Address of the directory authority.",
        type=str,
        default="127.0.0.1"
    )
    parser_dirinfo.add_argument(
        "--authority-dirport",
        help="Dir port of the directory authority.",
        type=int,
        default=80
    )
    parser_dirinfo.add_argument(
        "--authority-orport",
        help="OR port of the directory authority.",
        type=int,
        default=443
    )
    parser_dirinfo.add_argument(
        "--authority-contact",
        help="Contact info for the directory authority.",
        type=str,
        default="EPFL / SPRING Lab"
    )
    parser_dirinfo.add_argument(
        "--consensus",
        help="File in which to write the generated consensus.",
        type=Path,
        default="consensus.txt"
    )
    parser_dirinfo.add_argument(
        "--consensus-validity-days",
        help="Number of days that the consensus should be valid.",
        type=int,
        default=7
    )
    parser_dirinfo.add_argument(
        "--microdescriptors",
        help="File in which to write the microdescriptors of the selected routers.",
        type=Path,
        default="microdescriptors.txt"
    )
    parser_dirinfo.add_argument(
        "-n",
        "--number-routers",
        help="Number of routers to select from the consensus.",
        type=int,
        default=120
    )

    parser_dirinfo.set_defaults(callback=generate_customized_consensus_cb)

    parser_churn.add_argument(
        "--churn",
        help="File in which to write the computed churn.",
        type=Path,
        default="churn.txt"
    )
    parser_churn.add_argument(
        "--consensus",
        help="File in which to read the consensus generated with this script.",
        type=Path,
        default="consensus.txt"
    )

    parser_churn.set_defaults(callback=generate_churninfo_cb)

    namespace = parser.parse_args(arguments)

    if "callback" in namespace:
        #try:
        namespace.callback(namespace)
        #except Exception as err:
        #    LOGGER.error(err)
        #    sys.exit(1)

    else:
        parser.print_help()



if __name__ == "__main__":
    main(sys.argv[0], sys.argv[1:])
