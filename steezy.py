#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
# See LICENSE. schrodinger@konundrum.org.
"""Steezy Yara rule Generator.

Python script written to make a lazy Irish person do less work.
"""

import re
import sys
import logging
import argparse
from pprint import PrettyPrinter

import r2pipe
from mkyara import YaraGenerator
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64

pp = PrettyPrinter(indent=4)
logger = logging.getLogger(__name__)
re_chunk = re.compile('^\$chunk.+ = (\{[^\}]+\})')

# Hey mkYara - Yoink!
# Taken from Fox-It mkYara, https://github.com/fox-it/mkyara
class StringType():
    STRING = 1
    HEX = 2
    REGEX = 3

def mk_yara(opcodes, bits=32):

    if bits == 32:
        # CS_MODE_32
        gen = YaraGenerator("normal", CS_ARCH_X86, CS_MODE_32)
    elif bits == 64:
        # CS_MODE_64
        gen = YaraGenerator("normal", CS_ARCH_X86, CS_MODE_64)

    logger.debug("Performing mk_yara analysis")
    gen.add_chunk(opcodes, offset=0x0)

    rule = gen.generate_rule()
    mk_yara_getrule(rule)
    rule_str = rule._writer.contents()
    logger.debug(rule_str)
    return rule_str.replace('\t', ' ').replace('\n', '')

# Hey mkYara - Yoink!
# Taken from Fox-It mkYara, https://github.com/fox-it/mkyara
def mk_yara_getrule(rule):
    for s in rule.strings:
        if s.string_type == StringType.STRING:
            rule._writer.writeline('{} = "{}"'.format(s.key, s.value))
        elif s.string_type == StringType.HEX:
            rule._writer.writeline('{} = {{'.format(s.key, s.value))
            rule._writer.indent()
            value = s.value.rstrip('\n')
            rule._writer.write_block(value)
            rule._writer.dedent()
            rule._writer.writeline("}")
        else:
            raise Exception("not implemented!")

    rule._writer.dedent()
    rule._writer.writeline("")

def get_r2(filepath: str):

    r2 = r2pipe.open(filepath, flags=['-2'])
    r2.cmd('aaf;aac;aap')

    return r2

def gen_r2_yara_wild(r2, fcn_va):

    r2.cmd(f"s {fcn_va}")
    fcn_disassembly = r2.cmdj(f"pdfj @ {fcn_va}")
    fcn_ops = fcn_disassembly['ops']

    rule = ""

    for op in fcn_ops:

        # {'offset': 5368732036, 'size': 1, 'type': 'invalid'}
        type = op['type']

        if type == 'invalid':
            logging.error("Something invalid")
            logging.error(op)
            continue

        # Get current VA
        va = op['offset']

        j_instr = r2.cmdj(f"aoj@{va}")

        for instr in j_instr:

            fcn_hex_bytes = instr['bytes']

            # TODO: modrm nibbles.
            #if 'modrm' in instr['opex'] and\
            #    instr['opex']['modrm'] is True:

            logging.debug("Disasm: %s " % instr['disasm'])

            fcn_bytes = bytes.fromhex(fcn_hex_bytes)

            mask = bytes.fromhex(instr['mask'])

            result = bytearray()

            for i in range(len(fcn_bytes)):
                result.append(fcn_bytes[i] & mask[i])

            yara = result.hex().replace('00', '??')
            logging.debug("Yara string %s" % yara)
            rule += yara

    logging.debug("Yara rule %s" % rule)

    return f"$r2_wildcard_{fcn_va} = {{{rule}}}"

def gen_r2_yara_blocks(r2, fcn_va, file_bits):
    '''Generate a rule for the function's basic blocks.'''

    if file_bits == 32:
        range_max = '10'
    elif file_bits == 64:
        range_max = '6'

    rule = ""

    # Make sure r2 is at the beginning of the function.
    r2.cmd(f"s {fcn_va}")

    basic_blocks = r2.cmdj(f"afbj@{fcn_va}")

    for bb in basic_blocks:

        bb_addr = bb['addr']
        bb_ninstr = bb['ninstr']

        j_instr = r2.cmdj(f"aoj {bb_ninstr}@{bb_addr}")

        for instr in j_instr:

            instr_type = instr['type']

            if 'jmp' in instr_type:
                yara = f"[2-{range_max}]"
            else:
                fcn_hex_bytes = instr['bytes']

                logging.debug("Disasm: %s " % instr['disasm'])

                fcn_bytes = bytes.fromhex(fcn_hex_bytes)

                mask = bytes.fromhex(instr['mask'])

                result = bytearray()

                for i in range(len(fcn_bytes)):
                    result.append(fcn_bytes[i] & mask[i])

                yara = result.hex().replace('00', '??')

            logging.debug("Yara string %s" % yara)

            rule += yara

    logging.debug("Yara rule %s" % rule)

    return f"$r2_blocks_{fcn_va} = {{{rule}}}"

def gen_yara_rule(rules: dict, rulename=None):

    for file_md5 in rules:

        if rulename is None:
            rulename = f"steezy_{file_md5}"

        print(f"\nrule {rulename} {{\n")

        file_rules = rules[file_md5]

        meta = (
            "    meta:\n"
            f"        author = \"Steezy\"\n"
            f"        md5 = \"{file_md5}\"\n"
            )

        print(meta)
        print("    strings:\n")

        for fcn_va in file_rules:

            comment = f"// Function Virtual Address: {fcn_va}"

            print(f"        {comment}")

            fcn_rules = file_rules[fcn_va]

            for rule in fcn_rules:
                print(f"        {rule}")

            print()

        print("    condition:")
        print("        any of them")
        print("}")

class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('\n*** error: %s\n\n' % message)
        self.print_help()
        sys.exit(2)

def main():

    parser = MyParser(
            description='Generate Yara rule from function offsets.')

    parser.add_argument("-n", "--rulename")
    parser.add_argument("-f", "--filepath", required=True)
    parser.add_argument("-o", "--offsets", required=True, nargs='+')
    parser.add_argument("-v", "--verbose", action='store_true')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            format='[%(asctime)s] %(levelname)s: %(message)s',
            level=logging.DEBUG
        )
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(
            format='[%(asctime)s] %(levelname)s: %(message)s',
            level=logging.INFO
        )
        logging.getLogger().setLevel(logging.INFO)

    rules = {}

    r2 = get_r2(args.filepath)

    # file info
    file_info = r2.cmdj('iIj')
    file_bits = file_info['bits']
    file_md5 = r2.cmdj('itj')['md5']

    for fcn_va in args.offsets:

        r2.cmd(f"af@{fcn_va}")
        r2.cmd(f"s {fcn_va}")

        # TODO: Wasteful check to make sure luser didn't provide an
        # offset INTO a function, rather than the beginning of the
        # function?
        # Make sure we have the function VA
        #fcn_va = r2.cmdj(f"afij {va}")

        opcodes = r2.cmd('p8 $FS')

        # r2 rule(s)
        yara_r2_static = r2.cmd(f"pcy $FS @ {fcn_va}")
        yara_r2_static = re.sub(
            r'hex_[^\s]+', f"r2_static_{fcn_va}",
            yara_r2_static.strip())

        logging.debug(yara_r2_static)

        yara_r2_wild = gen_r2_yara_wild(r2, fcn_va)
        yara_r2_blocks = gen_r2_yara_blocks(r2, fcn_va, file_bits)

        yara_mkyara = mk_yara(bytes.fromhex(opcodes), file_bits)
        yara_mkyara = re.sub(
            r'chunk_[^\s]+', f"mkyara_{fcn_va}",
            yara_mkyara)

        if file_md5 not in rules.keys():
            rules[file_md5] = {}

        rules[file_md5][fcn_va] =\
            [yara_r2_static, yara_r2_wild, yara_r2_blocks, yara_mkyara]

    gen_yara_rule(
        rules,
        args.rulename)

if __name__ == '__main__':
    main()

# EOF
