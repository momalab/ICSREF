#!/usr/bin/env python

__author__ = 'Tasos Keliris'
"Modifications and improvements by w00kong"

# Imports
import sys
import os
import r2pipe
import angr
import re
import operator
import hashlib
import ujson
import dill
import struct
import logging
from difflib import SequenceMatcher
from glob import glob

logging.getLogger("angr").setLevel(logging.ERROR)

thisdir = os.path.split(__file__)[0]
trg_file = os.path.join(thisdir, 'data', '0750-0881.trg')

class Program():
    """
    **Program class**
       
    Contains calls to Function class to instantiate objects for each function

    Object attributes:

    - path: Path of PRG file
    - name: Name of PRG
    - hexdump: Bytes of PRG
    - program_start: Offset of program entry point
    - program_end: Offset of program end
    - dynlib_end: Offset of end of dynamic library strings
    - strings: PRG strings (>4 ASCII)
    - FunctionBoundaries: Start and end offsets of binary blobs (routines)
    - Functions: Contains <Function> objects (see Function class)
    - dynlibs_dict: Dictionary with dynamic calls
    - statlibs_dict: Dictionary with static calls
    - libs_dict: Dictionary with all calls
    - inputs: List of outputs
    - outputs: List of outputs

    """
    
    def __init__(self, path):
        """
        init function creates the Program object and does the analyses
        """
        # Program path
        self.path = path

        # Program name
        self.name = os.path.splitext(os.path.basename(self.path))[0]

        # Program hexdump
        self.hexdump = self.__read_file()
        print('DONE: Hexdump generation')

        # Analyze program header
        # ROM:00000004: End of strings
        # ROM:00000020: Entry point (OUTRO?) + 0x18 (==24)
        self.program_start = struct.unpack('I', self.hexdump[0x20:0x20+4])[0] + 24
        # ROM:0000002C: End of OUTRO? + 0x18 (==24)
        self.program_end = struct.unpack('I', self.hexdump[0x2C:0x2C+4])[0] + 24
        # ROM:00000044: End of dynamic libs (Before SYSDBGHANDLER)
        self.dynlib_end = struct.unpack('I', self.hexdump[0x44:0x44+4])[0]
        print('DONE: Header analysis')

        # Program strings
        self.strings = self.__strings()
        print('DONE: String analysis')

        # I/O analysis from trg file
        self.__find_io()
        print('DONE: I/O analysis')

        # Function Boundaries
        self.FunctionBoundaries = self.__find_blocks()
        print('DONE: Find function boundaries')

        # Program functions
        self.Functions = []
        
        self.__find_functions()
        print('DONE: Function disassembly')
        
        # Find all static and dynamic libraries and their offsets
        # Dynamic libraries
        self.dynlibs_dict = self.__find_dynlibs()
        print('DONE: Find dynamic calls')

        # Static libraries
        self.statlibs_dict = self.__find_statlibs()
        print('DONE: Find static calls')
        
        # All libraries: Add dynamic and static calls
        self.libs_dict = self.dynlibs_dict.copy()
        self.libs_dict.update(self.statlibs_dict)
        
        # Find library calls for each function
        self.__find_libcalls()
        print('DONE: Call offsets renaming')

        # Save object instance in file
        self.__save_object()


    def __find_io(self):
        """
        Find program INPUTS and OUTPUTS based on TRG information

        Assumes I/O memory locations will appear as direct offsets in the program
        and are kind of unique

        """

        # Read data from TRG file
        with open(trg_file, 'r') as f:
            trg_data = f.readlines()
        # Search for hex
        hex_pattern = re.compile('([0-9a-fA-F])*')
        # Find input_start, output_start, input_size, output_size
        for line in trg_data:
            if 'BaseAddressOfInputSegment' in line:
                input_start = re.search(hex_pattern, line.split('=')[1].replace('16#','')).group(0)
                input_start = int(input_start, 16)
            if 'BaseAddressOfOutputSegment' in line:
                output_start = re.search(hex_pattern, line.split('=')[1].replace('16#','')).group(0)
                output_start = int(output_start, 16)
            if 'SizeOfInputSegment' in line:
                input_size = re.search(hex_pattern, line.split('=')[1].replace('16#','')).group(0)
                input_size = int(input_size, 16)
            if 'SizeOfOutputSegment' in line:
                output_size = re.search(hex_pattern, line.split('=')[1].replace('16#','')).group(0)
                output_size = int(output_size, 16)

        # Find inputs/outputs offsets in the code
        self.inputs = {}
        self.outputs = {}
        for i in range(input_start, input_start + input_size, 1):
            match = self.__allindices(self.hexdump, struct.pack('<I', i))
            if match:
                self.inputs[hex(i)]=[hex(k) for k in match]
        for i in range(output_start, output_start + output_size, 1):
            match = self.__allindices(self.hexdump, struct.pack('<I', i))
            if match:
                self.outputs[hex(i)]=[hex(k) for k in match]
        return 0

    def __find_blocks(self):
        """
        Finds binary blobs (routines) based on the following delimiters:
         
        START: 0D C0 A0 E1 00 58 2D E9 0C B0 A0 E1

        STOP:  00 A8 1B E9

        """

        # Matches the prologue
        prologue = '\x0d\xc0\xa0\xe1\x00\x58\x2d\xe9\x0c\xb0\xa0\xe1'
        beginnings = self.__allindices(self.hexdump, prologue)
        # Matches the epilogue
        epilogue = '\x00\xa8\x1b\xe9'
        endings = self.__allindices(self.hexdump, epilogue)
        endings = [i+4 for i in endings]

        return zip(beginnings, endings)

    def __find_functions(self):
        """
        Produces disassembly listings for all functions
        """
        # Open an r2pipe to radare2 \m/
        r2=r2pipe.open(self.path)
        # Set r2 architecture configuration - Processor specific
        r2.cmd('e asm.arch=arm; e asm.bits=32; e cfg.bigendian=false')
        # Instantiate Functions
        for i in range(len(self.FunctionBoundaries)):
            # Code disassembly
            # Start: MOV, STMFD, MOV
            start_code = self.FunctionBoundaries[i][0]
            # Stop: LDMDB
            stop_code = self.FunctionBoundaries[i][1]
            length_code = stop_code - start_code
            disasm_code = r2.cmd('b {}; pD @{}'.format(length_code ,start_code))
            # Add spaces for formating purposes and consistency in disassembly string
            disasm_code = (12 * ' ' + disasm_code).split('\n')
            # Add data
            # Start at code stop
            start_data = stop_code
            # Stop at beginning of next (or special case for last function from header)
            if i == len(self.FunctionBoundaries)-1:
                stop_data = self.program_end
            else:
                stop_data = self.FunctionBoundaries[i+1][0]
            length_data = stop_data - start_data
            # Data disassembly
            disasm_data = r2.cmd('pxr {} @{}'.format(length_data ,start_data))
            disasm_data = disasm_data.split('\n')
            # Disassembly formating
            for i,line in enumerate(disasm_data):
                disasm_data[i] = '            {}     {}      {}'.format(line[:11], line[14:23], line [14:])
            disasm = disasm_code + disasm_data
            self.Functions.append(Function(self.path, start_code, stop_data, self.hexdump[start_code:stop_data], disasm))
        r2.quit()
        return 0

    def __find_dynlibs(self):
        """
        Finds dynamic libraries and their offsets
        """
        offset = self.dynlib_end
        # Reverse find 0xFFFF (offset for the beginning of strings)
        dynlib_offset = self.hexdump.rfind('\xff\xff',0,offset) + 2
        dynlibs = {}
        # Match printable ASCII characters
        dynlib = re.search('[ -~]*', self.hexdump[dynlib_offset:]).group(0)
        # Find the offsets to dynamic libs
        while dynlib:
            dynlib_offset += len(dynlib) + 1
            temp = self.hexdump[dynlib_offset:dynlib_offset+2].encode('hex')
            jump_offset = int(''.join([m[2:4]+m[0:2] for m in [temp[i:i+4] for i in range(0,len(temp),4)]]),16) * 4 + 8
            dynlibs[jump_offset] = dynlib
            dynlib_offset += 2
            dynlib = re.search('[ -~]*', self.hexdump[dynlib_offset:]).group(0)
        return dynlibs

    def __find_statlibs(self):
        entry_offset = self.Functions[-1].start
        stop_offset  = self.FunctionBoundaries[-1][1]-8
        funs = [x for x, _ in self.FunctionBoundaries]
        # Change 0x2000 location of writing address in OUTRO with 0x10000000 to not overwrite code
        code_start = '\x00\x20\x00\x00'
        with open('temphexdump.bin', 'w') as f:
            hexdump_mod = self.hexdump.replace(code_start, '\x00\x00\x00\x10')
            f.write(hexdump_mod)
        proj = angr.Project('temphexdump.bin', load_options={'main_opts': {'backend': 'blob', 'custom_base_addr': 0, 'custom_arch':'ARMEL', 'custom_entry_point':0x50}, 'auto_load_libs':False})
        state = proj.factory.entry_state()
        state.regs.pc = entry_offset
        simgr = proj.factory.simulation_manager(state)
        # Initialize some (0xFF) mem locations so taht execution doesn't jump to end.
        for i in range(0,0xFF,4):
            simgr.active[0].mem[simgr.active[0].regs.r0 + i].long = 0xFFFFFFFF
        # Run the code to create the static offsets in memory
        simgr.explore(find=stop_offset)
        statlibs = {}
        i = 0
        while len(statlibs) < len(funs) - 1:
            mem_val = state.solver.eval(simgr.found[0].mem[simgr.found[0].regs.r1 + i].int.resolved)
            if mem_val in funs:
                statlibs[i + 8] = 'sub_{:x}'.format(mem_val)
            i += 4
        os.remove('temphexdump.bin')
        return statlibs

    def __find_libcalls(self):
        """
        Finds the calls from all functions (dynamic and static)
        """
        for func in self.Functions:
            for index, line in enumerate(func.disasm):
                # Jump register can be other than r8
                if 'mov pc, r' in line:
                    i=3
                    # Go backwards until ldr r in line
                    while not re.search('ldr r[0-9], \[0x', func.disasm[index-i]):
                        i += 1
                    jump = func.disasm[index-i].split(';')[1].split('=')[1].rstrip()
                    # Format jump address (if hex)
                    if '0x' in jump:
                        jump = int(jump, 16)
                    jump = int(jump)
                    # Annotate disassembly
                    lib_name = self.libs_dict[jump]
                    func.disasm[index] += '                  ; call to {}'.format(lib_name)
                    if lib_name not in func.calls.keys():
                        func.calls[lib_name] = 1
                    else:
                        func.calls[lib_name] += 1
        return 0

    def __read_file(self):
        """
        Reads hexdump from file
        """
        with open(self.path, 'rb') as f_in:
            file_bytes = f_in.read()
        return file_bytes

    def __save_object(self):
        """
        Serializes the object instance and saves it to a file using the dill module
        """
        # Create directory for output results
        path = os.path.join('results', self.name)
        try: 
            os.makedirs(path)
        except OSError:
            if not os.path.isdir(path):
                raise
        dat_f = os.path.join(path, '{}_init_analysis.dat'.format(self.name))
        
        with open(dat_f, 'w') as f:
            dill.dump(self, f)

    def __allindices(self, file_bytes, sub, offset=0):
        """
        Finds all occurrences of substring
            
        :param: file_bytes: bytes to perform the search on
        :param: sub: substring to search for in file_bytes
        """

        i = file_bytes.find(sub, offset)
        listindex=[]
        while i >= 0:
            listindex.append(i)
            i = file_bytes.find(sub, i + 1)
        return listindex
    
    def __strings(self):
        """
        Finds consecutive <= 4-byte ASCII character strings
        """
        strings = {}
        p=re.compile('([ -~]{4,})')
        for m in p.finditer(self.hexdump):
            strings[m.start()] = m.group()
        return strings

class Function():
    """
    **Function class**

    Object attributes:

    - path: Path of PRG file
    - start: Offset of function in PRG
    - offset: Offset of function in PRG
    - length: Length in bytes of function
    - hexdump: Bytes of specific function
    - disasm: Disassembly listing of function
    - hash: SHA256 hash digest of function opcodes
    - calls: Calls to other dynamic or static locations from function

    """

    def __init__(self, path, start, stop, hexdump, disasm):
        """
        Function initialization
        """
        # Path
        self.path = path
        # Function start offset
        self.start = start
        self.offset = start
        # Function name. Convention: sub_<offset>
        self.name = 'sub_{:x}'.format(self.start)
        # Function stop offset
        self.stop = stop
        # Function length in bytes
        self.length = stop - start
        # Hexdump of particular function
        self.hexdump = hexdump
        # Disassembly listing of particular function
        self.disasm = disasm
        # Create string with opcode sequences for hash matching
        op_str = ''
        for line in self.disasm:
            op = line[43:].split(' ')[0]
            # Discard data
            if len(op) < 6:
                op_str += line[43:].split(' ')[0]
        # Function opcodes SHA256 hash
        self.hash = hashlib.sha256(op_str).hexdigest()
        # Initialize list of calls from function. Gets populated later
        self.calls = {}

def main(argv):
    # Main function: Parses command line arguments
    # argv[0] is the input PRG file
    prg = Program(argv[0])

    # Print dynamic and static libraries and their calling offsets
    sort_libs = sorted(prg.libs_dict.items(), key = operator.itemgetter(0))
    for lib in sort_libs:
        print('{}\t{}'.format(hex(lib[0]), lib[1]))

    # Print the calls from each function
    for fun in prg.Functions:
        print('{}\t==>\t{}'.format(fun.name, fun.calls))

    return 0

# Call main with command line arguments
if __name__ == '__main__':
    main(sys.argv[1:])
