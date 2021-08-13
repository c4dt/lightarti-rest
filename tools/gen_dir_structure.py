#! /usr/bin/env python3

"""
Automate the generation of a directory structure
"""

from argparse import (
    ArgumentParser,
    Namespace
)
from datetime import (
    datetime,
    timedelta
)
from pathlib import Path
from posix import R_OK
from typing import List

import os
import sys

from stem.descriptor.networkstatus import KeyCertificate, NetworkStatusDocumentV3

from gen_fresh_dirinfo import (
    consensus_validate_signatures,
    fetch_certificates,
    fetch_latest_consensus,
    generate_certificate,
    generate_churninfo,
    generate_customized_consensus,
    InvalidConsensus,
    LOGGER
)

DIRNAME_AUTHORITY_PRIVATE = "private"
DIRNAME_AUTHORITY_PUBLIC = "public"

FILENAME_AUTHORITY_KEY_ID = "authority_identity_key"
FILENAME_AUTHORITY_KEY_SIGNATURE = "authority_signing_key"
FILENAME_AUTHORITY_FINGERPRINT = "authority.txt"
FILENAME_CERTIFICATE = "certificate.txt"
FILENAME_CHURN = "churn.txt"
FILENAME_CONSENSUS = "consensus.txt"
FILENAME_MICRODESCRIPTORS = "microdescriptors.txt"

#
# Feel free to modify these values as you see fit.
#

# Number of months for which the certificate should be valid.
CERTIFICATE_VALIDITY_MONTHS = 12

# Number of router to select for building the customized consensus.
CONSENSUS_NUMBER_ROUTERS = 120

# Minimal validity dUration of the customized consensus.
CONSENSUS_VALIDITY_DAYS = 14

# Feel free to modify these values as you want, they are used to fill fields in the certificate
# and customized consensus but do not impact on Lightarti-rest behavior.
AUTHORITY_NAME = "C4DT"
AUTHORITY_HOSTNAME = "c4dt.org"
AUTHORITY_IP_ADDRESS = "128.178.32.16"
AUTHORITY_DIR_PORT = 80
AUTHORITY_OR_PORT = 443
AUTHORITY_CONTACT = "https://www.c4dt.org"


class InconsistentDirectoryStructure(Exception):
    """
    The directory structure is not consistant.
    """


def fetch_valid_consensus() -> NetworkStatusDocumentV3:
    """
    Retrieve a fresh consensus from the network and verify its signature.

    :raises InvalidConsensus: the consensus is invalid
    :return: the fresh consensus
    """
    consensus = fetch_latest_consensus()
    v3idents = [auth.v3ident for auth in consensus.directory_authorities]
    key_certificates = fetch_certificates(v3idents)
    if not consensus_validate_signatures(consensus, key_certificates):
        raise InvalidConsensus("Validation of the consensus' signature failed.")

    return consensus


def ensure_dir_rw_access(directory: Path) -> None:
    """
    Ensures that a directory exists and that we have read/write access to it.

    :param directory: directory we want to ensure to have these properties
    :raises InconsistentDirectoryStructure: The directory does not have these properties.
    """
    if not directory.exists():
        directory.mkdir()

    if not directory.is_dir():
        raise InconsistentDirectoryStructure(f"File {directory} should be a directory.")

    if not os.access(directory, os.R_OK | os.W_OK):
        raise InconsistentDirectoryStructure(f"Directory {directory} do not have enough permission.")


def _ensure_file_access(filepath: Path, access_flags: int) -> None:
    """
    Ensures that a file exists and that we can have enough access rights to it.

    :param filepath: file we want to ensure to have these properties
    :param access_flags: access required to the file
    :raises InconsistentDirectoryStructure: The file does not have these properties.
    """

    if not filepath.is_file():
        raise InconsistentDirectoryStructure(f"File {filepath} does not exists.")

    if not os.access(filepath, access_flags):
        raise InconsistentDirectoryStructure(f"File {filepath} do not have enough permission.")


def ensure_file_r_access(filepath: Path) -> None:
    """
    Ensures that a file exists and that we have read access to it.

    :param filepath: file we want to ensure to have these properties
    :raises InconsistentDirectoryStructure: The file does not have these properties.
    """
    _ensure_file_access(filepath, os.R_OK)


def ensure_file_rw_access(filepath: Path) -> None:
    """
    Ensures that a file exists and that we have read/write access to it.

    :param filepath: file we want to ensure to have these properties
    :raises InconsistentDirectoryStructure: The file does not have these properties.
    """
    _ensure_file_access(filepath, os.R_OK | os.W_OK)


def ensure_valid_authority_dir(dir_auth: Path, date_utc: datetime) -> None:
    """
    Ensures that a directory contains the files required for a valid authority.

    :param dir_auth: directory containing or to contain the authority files
    :param date_utc: date for which the authority should be valid (in UTC)
    :raises InconsistentDirectoryStructure: At least one of the authority file is invalid.
    """
    if not dir_auth.exists():
        LOGGER.info(f"Create new authority in {dir_auth}.")
        dir_auth.mkdir()
        update_authority_dir(dir_auth)

    if not dir_auth.is_dir():
        raise InconsistentDirectoryStructure(f"File {dir_auth} should be a directory.")

    if not os.access(dir_auth, os.R_OK):
        raise InconsistentDirectoryStructure(f"Directory {dir_auth} is not readable.")

    identity_key_path = dir_auth / DIRNAME_AUTHORITY_PRIVATE / FILENAME_AUTHORITY_KEY_ID
    ensure_file_r_access(identity_key_path)

    signing_key_path = dir_auth / DIRNAME_AUTHORITY_PRIVATE / FILENAME_AUTHORITY_KEY_SIGNATURE
    ensure_file_r_access(signing_key_path)

    certificate_path = dir_auth / DIRNAME_AUTHORITY_PUBLIC / FILENAME_CERTIFICATE
    ensure_file_r_access(certificate_path)
    certificate_raw = certificate_path.read_bytes()
    certificate = KeyCertificate(certificate_raw)

    authority_path = dir_auth / DIRNAME_AUTHORITY_PUBLIC / FILENAME_AUTHORITY_FINGERPRINT
    ensure_file_r_access(authority_path)

    if certificate.expires <= date_utc:
        LOGGER.info(f"Renew authority certificate in {dir_auth}.")
        ensure_file_rw_access(certificate_path)
        update_authority_dir(dir_auth)


def update_authority_dir(dir_auth: Path) -> None:
    """
    Update the authority information.

    :param dir_auth: directory to contain the authority information
    """
    private_dir = dir_auth / DIRNAME_AUTHORITY_PRIVATE
    public_dir = dir_auth / DIRNAME_AUTHORITY_PUBLIC

    ensure_dir_rw_access(private_dir)
    ensure_dir_rw_access(public_dir)

    identity_key_path = private_dir / FILENAME_AUTHORITY_KEY_ID
    signing_key_path = private_dir / FILENAME_AUTHORITY_KEY_SIGNATURE
    certificate_path = public_dir / FILENAME_CERTIFICATE
    authority_path = public_dir / FILENAME_AUTHORITY_FINGERPRINT

    generate_certificate(
        identity_key_path,
        signing_key_path,
        certificate_path,
        authority_path,
        AUTHORITY_NAME,
        CERTIFICATE_VALIDITY_MONTHS
    )


def create_current_dir(dir_auth: Path, dir_current: Path) -> None:
    """
    Create documents containing current info about the network's status.

    :param dir_auth: directory containing info about the directory authority
    :param dir_current: directory to contain the current info about the network's status
    """
    LOGGER.info(f"Create custom consensus in {dir_current}")

    dir_current.mkdir()

    signing_key_path = dir_auth / DIRNAME_AUTHORITY_PRIVATE / FILENAME_AUTHORITY_KEY_SIGNATURE
    certificate_path = dir_auth / DIRNAME_AUTHORITY_PUBLIC / FILENAME_CERTIFICATE
    consensus_path = dir_current / FILENAME_CONSENSUS
    microdescriptor_path = dir_current / FILENAME_MICRODESCRIPTORS

    generate_customized_consensus(
        signing_key_path,
        certificate_path,
        consensus_path,
        microdescriptor_path,
        CONSENSUS_NUMBER_ROUTERS,
        AUTHORITY_NAME,
        AUTHORITY_HOSTNAME,
        AUTHORITY_IP_ADDRESS,
        AUTHORITY_DIR_PORT,
        AUTHORITY_OR_PORT,
        AUTHORITY_CONTACT,
        CONSENSUS_VALIDITY_DAYS
    )


def update_churn(dir_document: Path, consensus_latest: NetworkStatusDocumentV3) -> None:
    """
    Update the info about churned routers.

    :param dir_document: directory containing the directory information to update.
    :param consensus_latest: latest consensus from the network
    """
    LOGGER.info(f"Update churn in {dir_document}")

    consensus_path = dir_document / FILENAME_CONSENSUS
    churn_path = dir_document / FILENAME_CHURN

    generate_churninfo(consensus_path, churn_path, consensus_latest)


def update_dir(dir_auth: Path, root: Path, date_utc: datetime) -> None:
    """
    Update the info about the network's status.

    :param dir_auth: directory containing info about the directory authority
    :param root: directory where to put all the network status information
    :param date_utc: current date and time in UTC
    """
    dir_current = root / date_utc.strftime("%Y%m%d")

    if not dir_current.exists():
        # create dir and generate custom consensus.
        create_current_dir(dir_auth, dir_current)
    else:
        consensus = fetch_valid_consensus()
        update_churn(dir_current, consensus)

    potential_documents_dirs = list()

    for dt_days in range(1, CONSENSUS_VALIDITY_DAYS):
        dir_documents_name: str = (date_utc - timedelta(days=dt_days)).strftime("%Y%m%d")
        potential_documents_dirs.append(dir_documents_name)

    for dir_documents_name in potential_documents_dirs:
        dir_documents = root / dir_documents_name
        # Update churn
        if dir_documents.is_dir():
            if os.access(dir_documents, os.R_OK | os.W_OK):
                consensus = fetch_valid_consensus()
                update_churn(dir_documents, consensus)
            else:
                raise InconsistentDirectoryStructure(f"Directory {dir_documents} is inconsistent.")


def directory_structure(namespace: Namespace) -> None:
    """
    Function to build or update a directory structure containing up-to-date network info.

    :param namespace: namespace containing the parsed arguments.
    """
    date_utc = datetime.utcnow()
    dir_auth: Path = namespace.authority_directory
    dir_root: Path = namespace.root_directory

    ensure_dir_rw_access(dir_root)
    ensure_valid_authority_dir(dir_auth, date_utc)

    update_dir(dir_auth, dir_root, date_utc)


def main(program: str, arguments: List[str]) -> None:
    """
    Entrypoint of the program. Parse the arguments, and call the correct function.

    :param program: name of the script.
    :param arguments: arguments passed to the program.
    """

    parser = ArgumentParser(prog=program)
    parser.add_argument(
        "--authority-directory",
        help="Directory containing files related to the Tor directory authority.",
        type=Path,
        default="authority"
    )
    parser.add_argument(
        "--root-directory",
        help="Directory containing up-to-date documents for using Lightarti-rest.",
        type=Path,
        default="documents-public"
    )

    namespace = parser.parse_args(arguments)

    try:
        directory_structure(namespace)
    except Exception as err:
        LOGGER.error(err)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[0], sys.argv[1:])
