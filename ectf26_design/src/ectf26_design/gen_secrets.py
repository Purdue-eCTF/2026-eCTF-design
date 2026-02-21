"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path

from Crypto.Random import get_random_bytes
from Crypto.Signature import eddsa
from loguru import logger


def pub_from_priv_bytes(key: bytes) -> str:
    return eddsa.import_private_key(key).public_key().export_key(format="raw").hex()


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """

    all_secrets = {
        "groups": {},
    }

    for group in groups:
        group_data = {"public_keys": {}, "secret_keys": {}, "shared_symmetric": {}}

        write_priv = get_random_bytes(32)
        read_priv = get_random_bytes(32)
        transfer_priv = get_random_bytes(32)
        interrogate_priv = get_random_bytes(32)

        # Generate all keys, since the access controls only get passed to the dockerfile
        group_data["public_keys"]["pk_sign"] = pub_from_priv_bytes(write_priv)
        group_data["public_keys"]["pk_read"] = pub_from_priv_bytes(read_priv)
        group_data["public_keys"]["pk_trans"] = pub_from_priv_bytes(transfer_priv)
        group_data["public_keys"]["pk_inter"] = pub_from_priv_bytes(interrogate_priv)

        group_data["secret_keys"]["sk_sign"] = write_priv.hex()
        group_data["secret_keys"]["sk_read"] = read_priv.hex()
        group_data["secret_keys"]["sk_trans"] = transfer_priv.hex()
        group_data["secret_keys"]["sk_inter"] = interrogate_priv.hex()

        group_data["shared_symmetric"] = {
            "T0": get_random_bytes(32).hex(),
            "T1": get_random_bytes(32).hex(),
            "I0": get_random_bytes(32).hex(),
            "I1": get_random_bytes(32).hex(),
        }

        all_secrets["groups"][f"{group}"] = group_data

    return json.dumps(all_secrets).encode()


def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {args.secrets_file.absolute()}")


if __name__ == "__main__":
    main()
