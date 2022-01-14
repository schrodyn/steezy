# -*- coding: utf-8 -*-
""" Steezy """

import sys

import logging
import string
import os.path
import steezy

from steezy.lib import MyParser
from argparse import ArgumentTypeError

logger = logging.getLogger(__name__)

def file_exists(filepath: str) -> str:
    """Check if the user filepath arg exists."""
    if not os.path.isfile(filepath):
        raise ArgumentTypeError(
            'File does not exist: {}'.format(filepath)
        )
    else:
        return filepath


def check_offset(offset: str) -> int:
    """Validate virtual address offset argument from user."""

    try:
        # TODO: Check if hex without prefix
        if offset.startswith('0x') or\
            all(c in string.hexdigits for c in offset):
            return int(offset, 16)
        else:
            return int(offset)
    except:
        raise ArgumentTypeError(
            'Invalid virtual address: {}'.format(offset)
        )

def check_range(offset_range: str) -> list:
    """Validate virtual address offset argument from user."""

    if ':' not in offset_range:
        raise ArgumentTypeError(
            'Invalid virtual address range: {}'.format(offset_range)
        )

    try:
        offsets = []
        for offset in offset_range.split(':'):
            # TODO: Check if hex without prefix
            if offset.startswith('0x') or\
                all(c in string.hexdigits for c in offset):
                offsets.append(int(offset, 16))
            else:
                offsets.append(int(offset))
        return offsets
    except:
        raise ArgumentTypeError(
            'Invalid virtual address: {}'.format(offset_range)
        )

def main():
    """Public Static Void Main()"""

    parser = MyParser(
        description='Steezy Ghetto Yara Rule Generator'
    )
    parser.add_argument(
        "-f", "--filepath",
        help="Target executable.",
        required=True,
        type=file_exists
    )

    arg_logging_group = parser.add_argument_group(
        'Logging', 'Define the level of logging.'
    )

    mxg = arg_logging_group.add_mutually_exclusive_group()
    mxg.add_argument(
        "-v", "--verbose", action='store_true', help="Debug output"
    )
    mxg.add_argument(
        "-q", "--quiet", action='store_true', help="Reduce output"
    )

    arg_va_group = parser.add_argument_group(
        'Virtual Addresses',
        'Provide either a function VA or a range of addresses.'
    )

    mxg = arg_va_group.add_mutually_exclusive_group(required=True)
    mxg.add_argument(
        "-o", "--offset",
        help="Function virtual address.",
        type=check_offset
    )
    mxg.add_argument(
        "-r", "--offset_range",
        help="Virtual address range. Format: <start_offset>:<end_offset>",
        type=check_range
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.getLogger().setLevel(logging.INFO)

    steezee = steezy.Steezy()
    steezee.open_file(args.filepath)

    if args.offset:
        steezee.gen_yara(args.offset)

    if args.offset_range:
        (start, end) = args.offset_range
        steezee.gen_yara(start, end)

