#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import os
import angr
import struct
import re
import logging

"""Assumptions:
1) Module only handles PID_FIXCYCLE
2) Calls to PID_FIXCYCLE are made only from the penultimate function (PLC_PRG?)
3) Values for arguments of interest are globally defined in GLOBAL_INIT or passed directly to FB
4) Difference between GLOBAL_INIT and PLC_PRG small enough so it can be assembled in 1 instruction (short jump)
"""
logging.getLogger("angr").setLevel(logging.ERROR)

class PID():
    """Class PID: instantiation of PID class
    *_f is floating point value
    *_i is int/hex value as it appears in hexdump"""
    def __init__(self):
        self.SET_POINT_f = 0
        self.SET_POINT_i = 0
        self.KP_f = 0
        self.KP_i = 0
        self.TN_f = 0
        self.TN_i = 0
        self.TV_f = 0
        self.TV_i = 0
        self.Y_MANUAL_f = 0
        self.Y_MANUAL_i = 0
        self.Y_OFFSET_f = 0
        self.Y_OFFSET_i = 0
        self.Y_MIN_f = 0
        self.Y_MIN_i = 0
        self.Y_MAX_f = 0
        self.Y_MAX_i = 0
        self.MANUAL_f = 0
        self.MANUAL_i = 0
        self.RESET_f = 0
        self.RESET_i = 0
        self.CYCLE_f = 0
        self.CYCLE_i = 0
        self.callto = -1
        self.stackbase = -1

def pidargs(self, args):
    """Find arguments to PID_FIXCYCLE calls using symbolic execution (angr)

    No args

    :Example:
    
        reversing\@icsref:$ pidargs
    
    """
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program.')
        return 0
    # self.do_hashmatch(None)

    # Check if PID_FIXCYCLE is in identified functions
    if len([x for x in prg.Functions if 'PID' in x.name ]) < 1:
    	print('No PID_FIXCYCLE functions identified. Cannot extract arguments.')
    	return 0

    # Find PID calls in penultimate function
    PLC_PRG_fun = prg.Functions[-2]#[x for x in prg.Functions if x.name == 'PLC_PRG'][0]
    PIDoffsets_index = []
    PIDoffsets_pc = []
    for index, line in enumerate(PLC_PRG_fun.disasm):
        if ('call to ' in line) and ('PID' in line):
            PIDoffsets_pc.append(int(re.findall(r'\S+', line)[0], 16))
            PIDoffsets_index.append(index)

    # Find offset in PID_FIXCYCLE FB for SB stack base (R9)
    a=[x for x in self.prg.Functions if 'PID' in x.name][0]
    sb_offset = int(re.search(r'\[.+?,.+?\]', a.disasm[3]).group(0).split(', ')[1][:-1], 16) - 0xC

    # If there are calls to PID_FIXCYCLE create list in prg object to hold the results
    if PIDoffsets_pc:
        prg.PIDcall = []

    # Find the start location of stack fixing for PID_FIXCYCLE
    for i in range(len(PIDoffsets_index)):
        # Start a new PID instance
        pidinstance = PID()
        pidinstance.callto = PIDoffsets_pc[i]

        # Create hexdump_mod - Not very efficient but meh
        # Entry point of GLOBAL_INIT function
        entry_offset = prg.Functions[0].start
        # Change LDMDB epilogue to 0xFFFFFFFF so that the simgr errors and doesn't go to empty state
        epilogue = '\x00\xa8\x1b\xe9'
        # GLOBALINIT start and stop locations to only change code there
        g_start = prg.FunctionBoundaries[0][0]
        g_stop = prg.FunctionBoundaries[0][1]
        # hexdump_mod contains the entire program
        branch_offset = (PLC_PRG_fun.start - g_stop - 4) / 4 + 0xea000000
        branch_target = struct.pack('<I', branch_offset)
        hexdump_mod = prg.hexdump[:g_stop].replace(epilogue, branch_target) + prg.hexdump[g_stop:]
        # Find the locations of MOV PC, LR and NOP them out (2 before and 2 after instructions)
        movpclr = '\x0f\xe0\xa0\xe1'
        nop = '\x00\x00\xa0\xe1'
        while movpclr in hexdump_mod:
            offset = hexdump_mod.find(movpclr)
            hexdump_mod = hexdump_mod[:offset - 8] + nop * 5 + hexdump_mod[offset + 12:]

        with open('temphexdump{}.bin'.format(i), 'w') as f:
            # Force angr to enter errored state (2 locations call PID)
            # pidcall1 = 0x2ccc
            PIDcall = PIDoffsets_pc[i]
            # pidcall2 = 0x2db8
            hexdump_mod = hexdump_mod[:PIDcall] + '\xff\xff\xff\xff' + hexdump_mod[PIDcall + 4:]
            # Find the locations of MOV PC, LR and NOP them out (2 before and 2 after instructions)
            f.write(hexdump_mod)

        # angr project to find arguments to PID calls
        proj = angr.Project('temphexdump{}.bin'.format(i), load_options={'main_opts': {'backend': 'blob', 'custom_arch':'ARMEL', 'custom_base_addr': 0, 'custom_entry_point':entry_offset}, 'auto_load_libs':False})
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.run()
        s1 = simgr.errored[0].state.copy()

        # Remove temp file
        os.remove('temphexdump{}.bin'.format(i))

        # Record stackbase
        pidinstance.stackbase = s1.solver.eval(s1.regs.r9)

        # Save arguments that go in PID_FIXCYCLE call
        '''
        FUNCTION_BLOCK PID_FIXCYCLE
        VAR_INPUT
            ACTUAL :REAL;               (* actual value, process variable *)
        +0x5C    SET_POINT:REAL;             (* desired value, set point *)
        +0x60    KP:REAL;                    (* proportionality const. (P)*)
        +0x64    TN:REAL;                    (* reset time (I) in sec *)
        +0x68    TV:REAL;                    (* rate time, derivative time (D) in sec*)
        +0x6C    Y_MANUAL:REAL;              (* Y is set to this value as long as MANUAL=TRUE *)
        +0x70    Y_OFFSET:REAL;              (* offset for manipulated variable *)
        +0x74    Y_MIN:REAL;                 (* minimum value for manipulated variable *)
        +0x78    Y_MAX:REAL;                 (* maximum value for manipulated variable *)
        +0x7C    MANUAL:BOOL;                (*  TRUE: manual: Y is not influenced by controller, FALSE: controller determines Y *)
        +0x7D    RESET:BOOL;                 (* reset: set Y output to Y_OFFSET and reset integral part *)
        +0x80    CYCLE:REAL;                 (* time in s between two calls *)
        END_VAR     
        VAR_OUTPUT      
            Y:REAL;                     (* manipulated variable, set value*)
            LIMITS_ACTIVE:BOOL:=FALSE;  (* true set value would exceed limits Y_MIN, Y_MAX *)
            OVERFLOW:BOOL:=FALSE;       (* overflow in integral part *)
        END_VAR
        VAR
            I: INTEGRAL;
            D: DERIVATIVE;
            TMDIFF: DWORD;
            ERROR: REAL;
            INIT: BOOL:=TRUE;
            Y_ADDOFFSET: REAL;
            KPcopy:REAL;
            TNcopy:REAL;
            TVcopy:REAL;
        END_VAR
        '''

        # SET_POINT
        SET_POINT_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x04].float.resolved)
        SET_POINT_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x04].int.resolved)
        pidinstance.SET_POINT_f = SET_POINT_f
        pidinstance.SET_POINT_i = SET_POINT_i
        # KP
        KP_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x08].float.resolved)
        KP_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x08].int.resolved)
        pidinstance.KP_f = KP_f
        pidinstance.KP_i = KP_i
        # TN
        TN_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x0C].float.resolved)
        TN_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x0C].int.resolved)
        pidinstance.TN_f = TN_f
        pidinstance.TN_i = TN_i
        # TV
        TV_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x10].float.resolved)
        TV_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x10].int.resolved)
        pidinstance.TV_f = TV_f
        pidinstance.TV_i = TV_i
        # Y_MANUAL
        Y_MANUAL_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x14].float.resolved)
        Y_MANUAL_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x14].int.resolved)
        pidinstance.Y_MANUAL_f = Y_MANUAL_f
        pidinstance.Y_MANUAL_i = Y_MANUAL_i
        # Y_OFFSET
        Y_OFFSET_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x18].float.resolved)
        Y_OFFSET_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x18].int.resolved)
        pidinstance.Y_OFFSET_f = Y_OFFSET_f
        pidinstance.Y_OFFSET_i = Y_OFFSET_i
        # Y_MIN
        Y_MIN_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x1C].float.resolved)
        Y_MIN_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x1C].int.resolved)
        pidinstance.Y_MIN_f = Y_MIN_f
        pidinstance.Y_MIN_i = Y_MIN_i
        # Y_MAX
        Y_MAX_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x20].float.resolved)
        Y_MAX_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x20].int.resolved)
        pidinstance.Y_MAX_f = Y_MAX_f
        pidinstance.Y_MAX_i = Y_MAX_i
        # MANUAL
        MANUAL_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x24].float.resolved)
        MANUAL_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x24].int.resolved)
        pidinstance.MANUAL_f = MANUAL_f
        pidinstance.MANUAL_i = MANUAL_i
        # RESET
        RESET_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x25].float.resolved)
        RESET_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x25].int.resolved)
        pidinstance.RESET_f = RESET_f
        pidinstance.RESET_i = RESET_i
        # CYCLE
        CYCLE_f = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x28].float.resolved)
        CYCLE_i = s1.solver.eval(s1.mem[s1.regs.r9 + sb_offset + 0x28].int.resolved)
        pidinstance.CYCLE_f = CYCLE_f
        pidinstance.CYCLE_i = CYCLE_i

        # Print output
        print('\nCall to PID at {}'.format(hex(PIDoffsets_pc[i])))
        print('SET_POINT = {}'.format(SET_POINT_f).ljust(32) + '({})'.format(hex(SET_POINT_i)))
        print('       KP = {}'.format(KP_f).ljust(32)        + '({})'.format(hex(KP_i)))
        print('       TN = {}'.format(TN_f).ljust(32)        + '({})'.format(hex(TN_i)))
        print('       TN = {}'.format(TV_f).ljust(32)        + '({})'.format(hex(TV_i)))
        print(' Y_MANUAL = {}'.format(Y_MANUAL_f).ljust(32)  + '({})'.format(hex(Y_MANUAL_i)))
        print(' Y_OFFSET = {}'.format(Y_OFFSET_f).ljust(32)  + '({})'.format(hex(Y_OFFSET_i)))
        print('    Y_MIN = {}'.format(Y_MIN_f).ljust(32)     + '({})'.format(hex(Y_MIN_i)))
        print('    Y_MAX = {}'.format(Y_MAX_f).ljust(32)     + '({})'.format(hex(Y_MAX_i)))
        print('   MANUAL = {}'.format(MANUAL_f).ljust(32)    + '({})'.format(hex(MANUAL_i)))
        print('    RESET = {}'.format(RESET_f).ljust(32)     + '({})'.format(hex(RESET_i)))
        print('    CYCLE = {}'.format(CYCLE_f).ljust(32)     + '({})'.format(hex(CYCLE_i)))

        # Add pidinstance to prg.PID
        prg.PIDcall.append(pidinstance)

    return 0