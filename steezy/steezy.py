# -*- coding: utf-8 -*-
"""Main Steezy Source."""

#import re
import logging

from steezy import r_pipe

logger = logging.getLogger(__name__)

class Steezy:
    """Main Steezy class."""

    def __init__(self):
        """Constructor."""

        self.filepath = None
        self.fileinfo = None
        self.r2z = None


    def open_file(self, filepath):
        """Process the input file."""

        self.filepath = filepath

        self.fileinfo = {
            'filepath': filepath
        }

        logger.info("Target file: %s", self.filepath)

        self.r2z = self._get_rpipe()

        logger.info('Analysing file.')

        self.r2z.cmd('aaa')


    def gen_yara(self, bva: int, eva: int = None):
        """
        Generate all Yara Strings for a given virtual address. If no
        distance is provided the VA will be treated as the location of a
        function.
        """

        yara_strings = []

        logger.debug(
            "Generating yara rule starting at virtual address: 0x%x",
            eva
        )

        if eva is None:
            self.r2z_define_function(bva)
            r2z_yara_blocks = self.get_r2z_yara_blocks(bva)
            logger.debug('r2z_yara_blocks: %s', r2z_yara_blocks)

            if r2z_yara_blocks not in yara_strings:
                yara_strings.append(r2z_yara_blocks)

        r2z_yara_static = self.get_r2z_yara_static(bva, eva)
        if r2z_yara_static not in yara_strings:
            yara_strings.append(r2z_yara_static)

        logger.debug('r2z_yara_static: %s', r2z_yara_static)

        r2z_yara_wild = self.get_r2z_yara_wild(bva, eva)
        if r2z_yara_wild not in yara_strings:
            yara_strings.append(r2z_yara_wild)

        logger.debug('r2z_yara_wild: %s', r2z_yara_wild)

        if eva is not None:
            distance = self.get_next_va(eva) - bva
            logger.debug(f'Distance: {distance}')
            cmd = f'p8 {distance}'
        else:
            cmd = 'p8 $FS'

        fbytes = bytes.fromhex(self.r2z.cmd(cmd))

        self._make_rule(yara_strings)


    def gen_r2z_yara_wild_range(self, bva: int, eva:int ):
        """Generate Yara string for a range of instructions."""

        logging.debug(f'Range: {bva:x}:{eva:x}')

        eva += self.r2z.cmdj(f'aoj @ {eva}')[0].get('size')

        logging.debug(f'Last VA: 0x{eva:x}')

        current_va = bva

        yara_str = ''

        while current_va < eva:
            logger.debug(f'Current VA: 0x{current_va:x}')
            j_instr = self.r2z.cmdj(f'aoj @ {current_va}')
            yara_str += self._instr_to_yara_str(j_instr)
            current_va += j_instr[-1].get('size')

        return f'{{{yara_str}}}'


    def r2z_define_function(self, fva: int, size = None) -> None:
        """Define the target virtual address as a function in r2/rz."""
        # TODO: Use the size to define a function of a given size.
        # Sometimes r2/rz's function analysis isn't as good as other
        # disassemblers or you need to define the function regardless.
        # Remember, can't change the ending address of a function. Need
        # to edit the defined blocks.
        # Command: afb

        # Analyse function at va.
        self.r2z.cmd(f'af @ {fva}')


    def get_next_va(self, va: int) -> int:
        """
        Given a virtual address, returns the address of the next instruction.
        """
        logger.debug("0x%x", va)
        return self.r2z.cmdj(f'aoj @ {va}')[0].get('addr')


    def get_r2z_yara_static(self, bva: int, eva: int = None) -> str:
        """
        Use r2/rz to generate a yara static hex string for a given
        function virual address.
        """
        # Analyse function. Seek to va.
        self.r2z.cmd(f's {bva}')

        if eva is not None:
            eva = self.get_next_va(eva)
            distance = eva - bva
            logger.debug('Distance: %s', distance)
            cmd = f'p8 {distance}'
        else:
            cmd = 'p8 $FS'

        logger.debug(f'cmd: {cmd}')

        opcodes = self.r2z.cmd(cmd).strip()
        str_opcodes = f'{{{opcodes}}}'

        return str_opcodes


    def get_r2z_yara_wild(self, bva: int, eva: int = None) -> str:
        """
        Use r2/rz to generate a yara wildcard hex string for a given
        virtual address.
        """

        if eva is not None:
            yara_str = self.gen_r2z_yara_wild_range(bva, eva)
            return yara_str
        else:
            yara_str = ''

            fcn_disassembly = self.r2z.cmdj(f'pdfj @ {bva}')

            fcn_ops = fcn_disassembly['ops']

            for op in fcn_ops:
                op_type = op['type']

                # TODO: Needed anymore?
                if op_type == 'invalid':
                    logging.error('Invalid op type! %s', op)
                    continue

                instr_va =  op['offset']

                j_instr = self.r2z.cmdj(f'aoj @ {instr_va}')
                yara_str += self._instr_to_yara_str(j_instr)

            return f'{{{yara_str}}}'


    def get_r2z_yara_blocks(self, fva: int) -> str:
        """
        Use r2/rz to generate a yara hex string for the code blocks with
        a given function virual address. This will change branching
        instrutions to yara range values.
        """

        yara_str = ''

        # Analyse function. Seek to va.
        self.r2z.cmd(f's {fva}')

        code_blocks = self.r2z.cmdj(f"afbj @ {fva}")

        if len(code_blocks) == 1:
            return None

        for cb in code_blocks:
            bb_va = cb['addr']
            bb_ninstr = cb['ninstr']

            j_instr = self.r2z.cmdj(f"aoj {bb_ninstr} @ {bb_va}")

            yara_str += self._instr_to_yara_str(j_instr, True)

        return f'{{{yara_str}}}'


    def _instr_to_yara_str(self, j_instr: list, mask_branch=False) -> str:
        """Turn r2/rz list of instruction dict into hex string."""

        hex_str =''

        bits = self.r2z.cmdj('iIj').get('bits')

        if bits not in (32, 64):
            raise ValueError("Invalid file bits %s" % bits)

        if bits == 32:
            range_max = 6
        elif bits == 64:
            range_max = 10

        for instr in j_instr:
            instr_type = instr['type']

            if mask_branch and 'jmp' in instr_type:
                hex_str += f"[2-{range_max}]"
            else:
                logger.debug("Disasm: %s " % instr['disasm'])

                fcn_bytes = bytes.fromhex(instr['bytes'])
                mask = bytes.fromhex(instr['mask'])
                result = bytearray()

                for i, b in enumerate(fcn_bytes):
                     result.append(b & mask[i])

                bytes_masked = result.hex().replace('00', '??')
                hex_str += bytes_masked

        return hex_str


    def get_fcn_md5(self, fva: int) -> str:
        """Generate an MD5 for the function bytes."""
        self.r2z.cmd(f's {fva}')
        return self.r2z.cmd('ph md5 @!$FS').strip()


    def _get_rpipe(self):
        r2z = r_pipe.open(self.filepath, flags=['-2'])
        #r2z = r_pipe.open(self.filepath)
        return r2z

    def _make_rule(self, yara_strings: list) -> str:

        sha256 = self.r2z.cmdj('itj').get('sha256')

        rule = '''
rule steezy_{}
{{
    meta:
        author = "Steezy (https://github.com/schrodyn/steezy)"
        hash1 = "{}"

    strings:
{}
    condition:
        any of them
}}
        '''

        strings_body = ''

        for (i, yara_str) in enumerate(yara_strings):
            #s = re.sub('(?<=[a-f0-9])(?:\?\?){2,10}(?!})', self._tidy_yara_str, yara_str)
            strings_body += f'        $a{i} = {yara_str}\n'

        print(rule.format(sha256, sha256, strings_body))
