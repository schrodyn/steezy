'''Steezy cli interface.'''

import sys
import string
import logging
import os.path
import argparse

import steezy

logger = logging.getLogger(__name__)

class MyParser(argparse.ArgumentParser):
    """Custom argparser error message."""

    def error(self, message):
        sys.stderr.write(f'\n*** error: {message}\n\n')
        self.print_help()
        sys.exit(2)

def file_exists(filepath: str) -> str:
    """Check if the user filepath arg exists."""
    if not os.path.isfile(filepath):
        raise argparse.ArgumentTypeError(
            'File does not exist: ', str(filepath)
        )
    return filepath


def check_offset(offset: str) -> int:
    """Validate virtual address offset argument from user."""

    try:
        if offset.startswith('0x') or\
            all(c in string.hexdigits for c in offset):
            return int(offset, 16)
        return int(offset)
    except Exception as exc:
        raise argparse.ArgumentTypeError(
            'Invalid virtual address: ', str(offset)
        ) from exc

def check_range(offset_range: str) -> list:
    """Validate virtual address offset argument from user."""

    if ':' not in offset_range:
        raise argparse.ArgumentTypeError(
            'Invalid virtual address range: ', str(offset_range)
        )

    try:
        offsets = []
        for offset in offset_range.split(':'):
            if offset.startswith('0x') or\
                all(c in string.hexdigits for c in offset):
                offsets.append(int(offset, 16))
            else:
                offsets.append(int(offset))
        return offsets
    except Exception  as exc:
        raise argparse.ArgumentTypeError(
            'Invalid virtual address: ', str(offset_range)
        ) from exc

def main():
    """Public Static Void Main()"""

    parser = MyParser(
        description='Steezy - Ghetto Yara Rule Generator'
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
    steezee.load_file(args.filepath)

    if args.offset:
        hex_strings = steezee.gen_yara(args.offset)
        print(steezee.make_rule(hex_strings))

    if args.offset_range:
        (start, end) = args.offset_range
        hex_strings = steezee.gen_yara(start, end)
        print(steezee.make_rule(hex_strings))
