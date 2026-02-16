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
import secrets
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Cipher import ChaCha20_Poly1305 # XChaCha is included in this
from loguru import logger


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
    # TODO: Update this function to generate any system-wide secrets needed by
    #   your design

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers
    all_secrets = {
        "groups": groups,
    }

    # 32 random bytes (and double check that they're random using secrets.toke_bytes)
    gid = 0
    for group in groups:
        group_data = {
            "public_keys": {},
            "secret_keys": {},
            "shared_symmetric": {}
        }

        write_keypair = ECC.generate(curve='Ed25519')
        read_keypair = ECC.generate(curve='Ed25519')
        transfer_keypair = ECC.generate(curve='Ed25519')
        interrogate_keypair = ECC.generate(curve='Ed25519')

        # Adding all keys for now since no knowledge (as of 2/16) of which perms the group has
        # Can add control flow based on perms here later
        group_data["public_keys"]["pk_sign"] = write_keypair.public_key().export_key(format='DER').hex()
        group_data["public_keys"]["pk_read"] = read_keypair.public_key().export_key(format='DER').hex()
        group_data["public_keys"]["pk_trans"] = transfer_keypair.public_key().export_key(format='DER').hex()
        group_data["public_keys"]["pk_inter"] = interrogate_keypair.public_key().export_key(format='DER').hex()

        group_data["secret_keys"]["sk_sign"] = write_keypair.export_key(format='DER').hex()
        group_data["secret_keys"]["sk_read"] = read_keypair.export_key(format='DER').hex()
        group_data["secret_keys"]["sk_trans"] = transfer_keypair.export_key(format='DER').hex()
        group_data["secret_keys"]["sk_inter"] = interrogate_keypair.export_key(format='DER').hex()

        group_data["shared_symmetric"] = {
            "T0": secrets.token_hex(32),
            "T1": secrets.token_hex(32),
            "I0": secrets.token_hex(32),
            "I1": secrets.token_hex(32)
        }

        all_secrets[gid] = group_data
        gid += 1

    # NOTE: if you choose to use JSON for your file type, you will not
    # be able to store binary data, and must either use a different file
    # type or encode the binary data to hex, base64, or another type of
    # ASCII-only encoding

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

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
