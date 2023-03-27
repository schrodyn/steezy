'''
Main Steeezy class.
'''

import os
import errno
import logging

from typing import List
from datetime import date
from pprint import PrettyPrinter

from steezy import r_pipe

pp = PrettyPrinter(indent=4)
logger = logging.getLogger(__name__)

class Steezy:
    '''Class representing the main Steezy object.

    Attributes:
        r2z (rzpipe | r2pipe): r2z pipe.
    '''

    def __init__(self, r2z: r_pipe.open = None) -> None:
        '''Initialises a steezy instance.

        Args:
            r2z: Optional argument to pass in your own radare2 / rizin pipe.
        '''

        self._r2z = r2z

    @property
    def r2z(self):
        '''radare2 / rizin open property.

        This is the r2pipe or the rz-pipe open() object. Steezy will
        create this when load_file() is called or you can set this to
        your own instance.
        '''
        return self._r2z

    @r2z.setter
    def r2z(self, value):
        self._r2z = value

    def load_file(self, filepath: str, analyse: bool = True) -> bool:
        '''Loads the target file and performs analysis.

        Target file is expcted to be a fully formed support executable
        (PE, EXE, MACH-O). The file is loaded into a radare2 / rizin
        session and 'aaa' analysis is performed.

        Args:
            filepath: Target filepath.

        Raises:
            FileNotFoundError: If the file does not exist.

        Returns:
            success: If the file was loaded successfully.
        '''

        if os.path.isfile(filepath) is False:
            raise FileNotFoundError(errno.ENOENT,
                                    os.strerror(errno.ENOENT), filepath)

        #self.r2z = r_pipe.open(filepath, flags=['-2'])
        self.r2z = r_pipe.open(filepath)

        if self.r2z:
            if analyse:
                logger.info('Analysing file: %s.', filepath)
                self.cmd('aaa')
            return True

        return False

    def gen_yara(self, bva: int, eva: int = None)  -> List[str]:
        '''Generate all hex strings for a given virtual address.

        For a provided virtual address yara strings are generated. If the
        argument `eva` is NOT provided it is assumed that the argument
        `bva` is the virtual address of a function. If both `bva` and
        `eva` are provided the yara strings will represent all assembly
        instructions within that range (eva inclusive).

        Args:
            bva: Starting offset.
            eva: Ending offset.

        Returns:
            yara_strings: A list of yara hex strings both static an wildcards
            representing the disassembled instructions.
        '''

        yara_strings = []

        if eva is None: # Assume function.

            # Analyse function. r2z's analysis doesn't always recognise functions as
            # well as every other disassembler so we make sure the function was recognised.
            self.define_function(bva)

            # Generate static and wildcard hex strings.
            for mask in (False, True):
                # Get function strings
                yara_str = self.get_yara_function(bva, mask)
                if yara_str not in yara_strings:
                    yara_strings.append(yara_str)
        else: # Act on a range of instructions.
            for mask in (False, True):
                yara_str = self.get_yara_range(bva, eva, mask)
                if yara_str not in yara_strings:
                    yara_strings.append(yara_str)

        return yara_strings

    def get_yara_function(self, fva: int, mask: bool = False) -> str:
        '''Generate hex string for a function.

        For a given function virtual address this will generate a hex
        string for the instructions.

        Args:
            fva: The function virtual address.
            mask: Toggle masking of bytes and branch instructions.

        Returns:
            func_string: A hex string representing bytes for the range
            of instructions.
        '''

        func = self.cmdj(f'pdfj @ {fva}')
        offsets = [instruction.get('offset') for instruction in func.get('ops')]
        func_string = self._instr_to_yara_str(offsets, mask)

        return func_string

    def get_yara_range(self, bva:int, eva:int, mask: bool = False) -> str:
        '''Generate a hex string for a range of instructions.

        Args:
            bva: The starting virtual address.
            eva: The ending virtual address (inclusive)
            mask: Toggle masking of bytes and branch instructions.

        Returns:
            yara_string: A yara hex string representing bytes for the
            range of instructions.
        '''

        # Calculate the number of bytes between addresses.
        logger.debug('bva: %s', hex(bva))
        logger.debug('eva: %s', hex(eva))
        logger.debug('mask: %s', str(mask))

        eva_instr_info = self.cmdj(f'aoj @ {eva}')[0]
        num_bytes = (eva + eva_instr_info.get('size')) - bva

        # Dump a list of N bytes of instructions from the starting virtual address.
        instructions: List[dict] = self.cmdj(f'pDj {num_bytes} @ {bva}')
        offsets = [instruction.get('offset') for instruction in instructions]

        yara_string = self._instr_to_yara_str(offsets, mask)
        return yara_string

    def define_function(self, fva: int) -> None:
        '''Define the target virtual address as a function in r2/rz.'''
        self.cmd(f'af @ {fva}')

    def get_r2z_yara_static(self, bva: int, eva: int = None) -> str:
        '''Generate a hex string for a function or range of bytes.

        This function doesn't support any masking. If `eva` is NOT none
        the generated hex string will represent the instsructions within
        the range `bva`<->`eva` inclusive. If `eva` is None `bva` is
        treated as the virtual address of a function and the hex string
        will represent the entire function.

        Args:
            bva: The starting virtual address.
            eva: The ending virtual address (inclusive)

        Returns:
            yara_string: A hex string representing bytes for the range
            of instructions.
        '''

        self.cmd(f's {bva}')

        if eva is not None:
            eva = self.get_next_va(eva)
            distance = eva - bva
            cmd = f'p8 {distance}'
        else:
            cmd = 'p8 $FS'

        opcodes = self.cmd(cmd).strip()
        yara_string = f'{opcodes}'
        return yara_string

    def get_next_va(self, va: int) -> int:
        '''Given a virtual address, returns the address of the next instruction.'''

        addr = self.cmdj(f'aoj @ {va}')[0].get('addr')
        size = self.cmdj(f'aoj @ {va}')[0].get('size')
        return self.cmdj(f'aoj @ {addr + size}')[0].get('addr')

    def cmd(self, cmd: str, **kwargs):
        '''Run an r2 command return string with result.'''
        return self.r2z.cmd(cmd, **kwargs)

    def cmdj(self, cmd: str, **kwargs):
        '''Same as cmd() but evaluates JSONs and returns an object.'''
        return self.r2z.cmdj(cmd, **kwargs)

    def _instr_to_yara_str(
            self,
            offsets: List[int],
            mask: bool = False
    ) -> str:
        '''Generate hex strings for a range of virtual addresses.

        For a supplied list of virtual addresses this will generate hex
        strings representing instructions at those addresses. Masking
        can be applied to the instructions making out operands from the
        instructions. This leverages the `mask` value returned from
        radare2/rizin to mask out the instruction bytes.

        Args:
            offsets: List of virtual addresses to generate hex strings.
            mask: Toggle masking of bytes and branch instructions.

        Returns:
            yara_string: A hex string representing bytes for the range
            of instructions.
        '''

        bits = self.cmdj('iIj').get('bits')
        if bits not in (32, 64):
            raise ValueError("Unsupport file bitness: ", str(bits))

        range_max = 15
        yara_string = ''

        for offset in offsets:
            instr = self.cmdj(f'aoj @ {offset}')[0]
            instr_type = instr.get('type')

            va = instr.get('addr')
            logger.debug('va: %s', va)

            disasm = instr.get('opcode')
            logger.debug('disasm: %s', disasm)

            instr_bytes = bytearray.fromhex(instr.get('bytes'))
            logger.debug('instr_bytes %s', instr_bytes.hex(" "))

            comment = f'// 0x{va:08x}: {disasm:35} ({instr_bytes.hex(" ")})\n'

            if mask and 'jmp' in instr_type:
                range_str = f"[2-{range_max}]"
                yara_string += (
                    f'            {range_str:<24} '
                    f'{comment}'
                )
            else:
                if mask:
                    byte_mask = bytes.fromhex(instr.get('mask'))
                    for i, b in enumerate(instr_bytes):
                        instr_bytes[i] = b & byte_mask[i]
                    yara_string += f'            {instr_bytes.hex(" ").replace("00", "??"):<24} '
                else:
                    yara_string += f'            {instr_bytes.hex(" "):<24} '

                yara_string += f'{comment}'

        return yara_string

    def make_rule(self, hex_strings: List[str]) -> str:
        '''Generate a Yara rule.

        This will take in a list of yara hex strings and prints a
        boilerplate yara rule using them.

        Args:
            hex_strings: List of strings for each hex string.

        Return:
            rule: The generated yara rule.
        '''

        created = date.today().isoformat()
        sha256 = self.cmdj('itj').get('sha256')

        rule = '''
rule steezy_{}
{{
    meta:
        author  = "Steezy (https://github.com/schrodyn/steezy)"
        hash    = "{}"
        created = "{}"

    strings:
{}
    condition:
        any of them
}}'''
        strings_body = ''

        for (i, yara_str) in enumerate(hex_strings):
            strings_body += (
                f'        $a{i} = {{\n'
                f'{yara_str}\n'
                f'        }}\n'
            )

        return rule.format(sha256, sha256, created, strings_body)
