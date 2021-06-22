#!/usr/bin/env python3

"""
Script to produce data to pass to Arti.
"""

import logging
from os import name
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
from datetime import (
    datetime,
    timedelta,
)
from hashlib import (
    sha1,
    sha256,
)
from heapq import nlargest
from math import ceil
from itertools import zip_longest
from pathlib import Path
from typing import List

from Crypto.PublicKey import RSA

from stem.descriptor import DocumentHandler
from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.networkstatus import (
    KeyCertificate,
    NetworkStatusDocumentV3,
)
from stem.descriptor.remote import (
    DescriptorDownloader,
    MAX_MICRODESCRIPTOR_HASHES,
)
from stem.descriptor.router_status_entry import RouterStatusEntryMicroV3


# Time format used in teh consensus.
CONSENSUS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Router flags in which we are interested.
FLAG_BAD_EXIT = "BadExit"
FLAG_EXIT = "Exit"
FLAG_FAST = "Fast"
FLAG_GUARD = "Guard"
FLAG_STABLE = "Stable"

# Format of an authority entry in the consensus (with a dummy vote digest).
AUTHORITY_FMT = """dir-source {nickname} {fingerprint} {addresses} {ports}
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

# Footer of the consensus included in the signature's hash (with many values already set).
CONSENSUS_FOOTER_IN_SIGNATURE = b"""directory-footer
bandwidth-weights Wbd=0 Wbe=0 Wbg=4273 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5727 Wgm=5727 Wmb=10000 Wmd=0 Wme=0 Wmg=4273 Wmm=10000
directory-signature """


class InvalidConsensus(Exception):
    """
    The consensus is invalid.
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


def fetch_latest_consensus() -> NetworkStatusDocumentV3:
    """
    Fetch the latest consensus from the network.

    :raises ValueError: Did not retrieve the expected consensus format.
    :return: the fresh consensus parsed by stem
    """
    downloader = DescriptorDownloader()

    # consensus validation does not seems to work
    consensus = downloader.get_consensus(
        document_handler=DocumentHandler.DOCUMENT,
        microdescriptor=True,
        #validate=True
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
    microdescriptors = list()
    buckets = [
        iter(r.microdescriptor_digest for r in routers)
    ] * MAX_MICRODESCRIPTOR_HASHES
    for bucket in zip_longest(*buckets):
        hashes = [h for h in bucket if h is not None]
        microdescriptors += downloader.get_microdescriptors(hashes=hashes, validate=True).run()

    for microdescriptor in microdescriptors:
        if not isinstance(microdescriptor, Microdescriptor):
            raise ValueError(f"Unexpected microdescriptor format {type(microdescriptor)}")

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
    consensus_b = consensus.get_bytes()
    signature_begin = consensus_b.find(b"\ndirectory-signature ") + 21
    consensus_digest = sha256(consensus_b[:signature_begin]).digest()

    num_valid = 0

    for certificate in key_certificates:

        signature = next(filter(lambda sig: sig.identity == certificate.fingerprint, consensus.signatures))
        if signature is None:
            continue

        public_key = RSA.import_key(certificate.signing_key)
        sign_match = re.search("-+BEGIN SIGNATURE-+\n([^-]+)\n-+END SIGNATURE-+", signature.signature)
        if sign_match is None:
            continue

        sign_b64 = sign_match.group(1)
        sign_b = b64decode(sign_b64)
        sign_i = int.from_bytes(sign_b, "big")

        m = public_key._encrypt(sign_i).to_bytes(public_key.size_in_bytes(), "big")
        recovered_hash_match = re.search(b"^\x00\x01\xff+\x00(.+)$", m, flags=re.DOTALL)
        if recovered_hash_match is None:
            continue

        recovered_hash = recovered_hash_match.group(1)

        if recovered_hash == consensus_digest:
            num_valid += 1

    return num_valid > (len(consensus.signatures) * 0.5)


def select_routers(
        consensus: NetworkStatusDocumentV3,
        number_routers: int,
        exit_ratio: float,
        guard_ratio: float = 0.5,
    ) -> List[RouterStatusEntryMicroV3]:
    """
    Select the routers with the highest available bandwidth matching the criteria.

    :param consensus: The consensus containing the routers descriptions
    :param guard_ratio: the minimal ratio of guards routers that we want
    :param exit_ratio: the minimal ratio of exit routers that we want
    :param n_routers: the final number of routers that we would like
    :raises ValueError: One of the parameter given in argument has an invalid value.
    :return: list of router entries matching the criteria of the selection
    """
    if guard_ratio < 0 or guard_ratio > 1:
        raise ValueError("Invalid ratio")

    if exit_ratio < 0 or exit_ratio > 1:
        raise ValueError("Invalid ratio")

    if number_routers > len(consensus.routers):
        raise ValueError("Not enough routers in consensus")

    n_guards = ceil(number_routers * guard_ratio)
    n_exits = ceil(number_routers * exit_ratio)

    # Sort routers by type.
    potential_guards: List[RouterStatusEntryMicroV3] = list()
    potential_exits: List[RouterStatusEntryMicroV3] = list()
    potential_middles: List[RouterStatusEntryMicroV3] = list()

    for router in consensus.routers.values():
        flags = set(router.flags)
        # We only consider stable routers
        # Which also have the guard flag to ensure a higher stability.
        if FLAG_STABLE in flags and FLAG_FAST in flags and FLAG_GUARD in flags:
            if FLAG_GUARD in flags:
                potential_guards.append(router)
            if FLAG_EXIT in flags and FLAG_BAD_EXIT not in flags:
                potential_exits.append(router)

            # We try to avoid using exit routers as potential middle nodes.
            if FLAG_EXIT not in flags:
                potential_middles.append(router)

    if n_guards > len(potential_guards):
        LOGGER.warning("Insufficient number of guard routers in the consensus.")

    if n_exits > len(potential_exits):
        LOGGER.warning("Insufficient number of exit routers in the consensus.")

    # We select the guards with the largest measured bandwidth.
    # Note that they can also act as exit nodes.
    guards = nlargest(n_guards, potential_guards, key=lambda r: r.bandwidth)

    selected_set = {router.fingerprint for router in guards}

    # We select the exit nodes which we do not have yet with the largest available bandwidth.
    # Note that they can also act as guards.
    exits = nlargest(n_exits, potential_exits, key=lambda r: r.bandwidth)

    for router in exits:
        selected_set.add(router.fingerprint)

    # We select some other routers based on their available bandwidth and provided we didn't
    # already select them.
    # Note that some might also act as guard or exit.
    n_middles = number_routers - len(selected_set)
    middles = nlargest(
        n_middles,
        potential_middles,
        key=lambda r: r.bandwidth if r.fingerprint not in selected_set else 0
    )

    for router in middles:
        selected_set.add(router.fingerprint)

    selected = sorted(selected_set, key=lambda fingerprint: int(fingerprint, 16))

    routers = [consensus.routers[fingerprint] for fingerprint in selected]

    return routers


def generate_signed_consensus(
        consensus: NetworkStatusDocumentV3,
        routers: List[RouterStatusEntryMicroV3],
        authority_signing_key: RSA.RsaKey,
        authority_certificate: KeyCertificate,
        authority_nickname: str,
        authority_addresses: str,
        authority_ports: str,
        authority_contact: str,
        consensus_lifetime: int
    ) -> bytes:
    """
    Generate a consensus with a custom set of routers, signed by a custom authority.

    :param consensus: original consensus
    :param routers: list of routers selected from the original consensus
    :param authority_signing_key: RSA key of the authority that need to sign the consensus
    :param authority_certificate: certificate of the authority that need to sign the consensus
    :param authority_nickname: nickname of the authority
    :param authority_addresses: IP addresses of the authority
    :param authority_ports: OR port and DIR port of the authority
    :param authority_contact: contact info of the authority
    :param consensus_lifetime: lifetime of the consensus in days
    :return: signed consensus with a subset of the routers
    """

    # Prepare the header of the consensus with corrected lifetime.
    valid_after = consensus.valid_after
    fresh_until = valid_after + timedelta(days=consensus_lifetime)
    valid_until = fresh_until + timedelta(days=consensus_lifetime)
    header = CONSENSUS_HEADER_FMT.format(
        valid_after=valid_after.strftime(CONSENSUS_TIME_FORMAT),
        fresh_until=fresh_until.strftime(CONSENSUS_TIME_FORMAT),
        valid_until=valid_until.strftime(CONSENSUS_TIME_FORMAT)
    ).encode("ascii")

    # Prepare our authority entry.
    authority = AUTHORITY_FMT.format(
        nickname=authority_nickname,
        fingerprint=authority_certificate.fingerprint,
        addresses=authority_addresses,
        ports=authority_ports,
        contact=authority_contact
    ).encode("ascii")

    # Compute the digest of the signing key.
    public_key_match = re.search(
        "-+BEGIN RSA PUBLIC KEY-+\n([^-]+)\n-+END RSA PUBLIC KEY-+",
        authority_certificate.signing_key
    )
    if public_key_match is None:
        raise ValueError("A certificate contains an invalid public key.")

    public_key_b64 = public_key_match.group(1)
    key_b = b64decode(public_key_b64)
    signing_key_digest = sha1(key_b).hexdigest().upper()

    # Tor do not follow the PKCS#1 v1.5 signature scheme strictly,
    # so we can not rely on a library to do it.
    consensus_unsigned = (
        header +
        authority +
        b"".join(r.get_bytes() for r in routers) +
        CONSENSUS_FOOTER_IN_SIGNATURE
    )
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


def generate_microdescriptors(microdescriptors: List[Microdescriptor]) -> bytes:
    """
    Generate microdescriptors document.

    :param microdescriptors: list of microdescriptors that need to be present in the file
    :return: bytes representation of the microdescriptors
    """
    return b"".join(m.get_bytes() for m in microdescriptors)


def create_custom_consensus(namespace: Namespace) -> None:
    """
    Create a custom consensus.

    :param namespace: namespace containing parsed arguments.
    """

    # Read the relevant input files related to the authority.
    authority_signing_key_path: Path = namespace.authority_signing_key
    with authority_signing_key_path.open("rb") as authority_signing_key_fd:
        authority_signing_key_raw = authority_signing_key_fd.read()

    authority_signing_key = RSA.import_key(authority_signing_key_raw)

    authority_certificate_path: Path = namespace.authority_certificate
    with authority_certificate_path.open("rb") as authority_certificate_fd:
        authority_certificate_raw = authority_certificate_fd.read()

    authority_certificate = KeyCertificate(authority_certificate_raw)

    consensus_original = fetch_latest_consensus()

    v3idents = [auth.v3ident for auth in consensus_original.directory_authorities]
    key_certificates = fetch_certificates(v3idents)

    # The validation provided by Stem does not seems to work with the tested version (1.8.0).
    # We implemented our own signature validation function.
    if not consensus_validate_signatures(consensus_original, key_certificates):
        raise InvalidConsensus("Signature validation failed.")

    number_routers: int = namespace.number_routers
    exit_ratio: float = namespace.exit_ratio
    routers = select_routers(consensus_original, number_routers, exit_ratio)

    authority_nickname: str = namespace.authority_nickname
    authority_addresses: str = namespace.authority_addresses
    authority_ports: str = namespace.authority_ports
    authority_contact: str = namespace.authority_contact
    consensus_lifetime: int = namespace.consensus_lifetime

    consensus = generate_signed_consensus(
        consensus_original,
        routers,
        authority_signing_key,
        authority_certificate,
        authority_nickname,
        authority_addresses,
        authority_ports,
        authority_contact,
        consensus_lifetime
    )

    our_consensus = NetworkStatusDocumentV3(consensus)
    if not consensus_validate_signatures(our_consensus, [authority_certificate]):
        raise InvalidConsensus("generated concensus has an invalid signature.")

    microdescriptors = fetch_microdescriptors(routers)

    microdescriptors_raw = generate_microdescriptors(microdescriptors)

    consensus_path: Path = namespace.consensus

    with consensus_path.open("wb") as consensus_fd:
        consensus_fd.write(consensus)

    microdescriptors_path: Path = namespace.microdescriptors


    with microdescriptors_path.open("wb") as microdescriptors_fd:
        microdescriptors_fd.write(microdescriptors_raw)


def main(program: str, arguments: List[str]) -> None:
    """
    Entrypoint of the program. Parse the arguments, and call the correct function.

    :param program: name of the script.
    :param arguments: arguments passed to teh program.
    """
    parser = ArgumentParser(prog=program)
    parser.add_argument(
        "--authority-signing-key",
        help="Signing key of the directory authority to sign the consensus.",
        type=Path,
        default="authority_signing_key"
    )
    parser.add_argument(
        "--authority-certificate",
        help="Certificate of the directory authority used to verify the consensus.",
        type=Path,
        default="authority_certificate"
    )
    parser.add_argument(
        "--authority-nickname",
        help="Nickname of the directory authority.",
        type=str,
        default="spring"
    )
    parser.add_argument(
        "--authority-addresses",
        help="Addresses of the directory authority for OR and DIR.",
        type=str,
        default="127.0.0.1 127.0.0.1"
    )
    parser.add_argument(
        "--authority-ports",
        help="Ports of the directory authority.",
        type=str,
        default="80 443"
    )
    parser.add_argument(
        "--authority-contact",
        help="Contact info for the directory authority.",
        type=str,
        default="EPFL/ SPRING Lab"
    )
    parser.add_argument(
        "--consensus",
        help="File in which to write the generated consensus.",
        type=Path,
        default="consensus.txt"
    )
    parser.add_argument(
        "--consensus-lifetime",
        help="Lifetime of the consensus in days.",
        type=int,
        default=7
    )
    parser.add_argument(
        "--exit-ratio",
        help="Minimal ratio of routers which can act as exit relays in the selected routers.",
        type=float,
        default=0.333
    )
    parser.add_argument(
        "--microdescriptors",
        help="File in which to write the microdescriptors of the selected routers.",
        type=Path,
        default="microdescriptors.txt"
    )
    parser.add_argument(
        "-n",
        "--number-routers",
        help="Number of routers to select from the consensus.",
        type=int,
        default=128
    )

    namespace = parser.parse_args(arguments)

    try:
        create_custom_consensus(namespace)
    except Exception as err:
        LOGGER.error(err)
        sys.exit(1)



if __name__ == "__main__":
    main(sys.argv[0], sys.argv[1:])
