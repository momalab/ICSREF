#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import ujson

def exp_pid_match(self, args):
    """
    Experimentally match PID functions. Signatures-based detection where 
    a binary is expected to contain specific constant values and have
    specific connections. See source code for more details.

    No args

    :Example:
    
        reversing\@icsref:$ exp_pid_match

    """
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program')
        return 0

    # Occurrences of 1000.0
    id1000 = '\x00\x00\x7A\x44'
    oc1000 = prg._Program__allindices(prg.hexdump, id1000)
    # Occurrences of 3.0
    id3 = '\x00\x00\x40\x40'
    oc3 = prg._Program__allindices(prg.hexdump, id3)
    # Occurrences of 1E38
    id1E38 = '\x99\x76\x96\x7E'
    oc1E38 = prg._Program__allindices(prg.hexdump, id1E38)
    # Occurrences of -1E38
    idnot1E38 = '\x99\x76\x96\xFE'
    ocnot1E38 = prg._Program__allindices(prg.hexdump, idnot1E38)
    # Occurrences of 1E38
    id1E30 = '\xCA\xF2\x49\x71'
    oc1E30 = prg._Program__allindices(prg.hexdump, id1E30)
    # Occurrences of -1E38
    idnot1E30 = '\xCA\xF2\x49\xF1'
    ocnot1E30 = prg._Program__allindices(prg.hexdump, idnot1E30)

    # Check if minimum occurrence of constants exists in hexdump, otherwise return
    if not (len(id1000) >= 2 and id3 and id1E38 and idnot1E38 and id1E30 and idnot1E30):
        return 0
    
    # Search for matches of BOTH main and init
    for func_index, func in enumerate(prg.Functions[:-2]):
        """
        DERIVATIVE:     3       (0x40400000)
                        1000    (0x447A0000)
        INTEGRAL:       1E38    (0x7E967699)
                        -1E38   (0xFE967699)
                        1000    (0x447A0000)
        PD:             
        PID:            1E30    (0x7149F2CA)
                        -1E30   (0xF149F2CA)
                        1000    (0x447A0000)
        PID_FIXCYCLE:   1E30    (0x7149F2CA)
                        -1E30   (0xF149F2CA)
                        1000    (0x447A0000)
        """
        
        # Initialize indices of possible locations
        maybe_PID = ''
        maybe_INTEGRAL = ''
        maybe_DERIVATIVE = ''

        # Check if it could be a PID function
        # if (id1E30 in func.hexdump) and (idnot1E30 in func.hexdump) and (id1000 in func.hexdump) and 'PID' not in func.name:
        if 'PID' not in func.name:
            maybe_PID = func_index
            for call in set(func.calls):
                if call not in prg.dynlibs_dict.values():
                    callindex = [i for i, j in enumerate(self.prg.Functions) if j.name == call]
                    if callindex:
                        callindex = callindex[0]
                        callfunc = self.prg.Functions[callindex]
                        # Check if call is DERIVATIVE
                        if (id3 in callfunc.hexdump) and (id1000 in callfunc.hexdump):
                            maybe_DERIVATIVE = callindex
                        # Check if call is INTEGRAL
                        if (id1E38 in callfunc.hexdump) and (idnot1E38 in callfunc.hexdump) and (id1000 in callfunc.hexdump):
                            maybe_INTEGRAL = callindex
            # If maybe_ 'flags' are set then bingo. Change names of experimental functions
            if maybe_PID and maybe_INTEGRAL and maybe_DERIVATIVE:
                print('Experimental module found function PID at 0x{:x}'.format(prg.Functions[maybe_PID].start))
                self.do___replace_callname([maybe_PID, 'exp_maybe_PID'])
                self.do___replace_callname([maybe_PID + 1, 'exp_maybe_PID_INIT'])
                self.do___replace_callname([maybe_DERIVATIVE, 'exp_maybe_DERIVATIVE'])
                self.do___replace_callname([maybe_DERIVATIVE + 1, 'exp_maybe_DERIVATIVE_INIT'])
                self.do___replace_callname([maybe_INTEGRAL, 'exp_maybe_INTEGRAL'])
                self.do___replace_callname([maybe_INTEGRAL + 1, 'exp_maybe_INTEGRAL_INIT'])
                return 0
    
    return 0
