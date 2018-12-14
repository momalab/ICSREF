#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import ujson
import os

def hashmatch(self, args):
    """
    Match known library functions with opcode hash technique

    No args

    :Example:
    
        reversing\@icsref:$ hashmatch
    
    """
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program')
        return 0

    # Signature file with deduplicated signatures
    thisdir = os.path.split(os.path.split(__file__)[0])[0]

    f_main = os.path.join(thisdir, 'data', 'MAIN_signatures.json')
    f_init = os.path.join(thisdir, 'data', 'INIT_signatures.json')

    with open(f_main, 'r') as f:
        main_data = f.readlines()
    with open(f_init, 'r') as f:
        init_data = f.readlines()

    # signatures is a list of dicts (jsons)
    main_sign = []
    init_sign = []
    for signature in main_data:
        main_sign.append(ujson.loads(signature))
    for signature in init_data:
        init_sign.append(ujson.loads(signature))

    num_funcs = len(prg.Functions)
    matched = []
    # Rename last function to PRG_INIT
    func_index = num_funcs - 1
    matched.append(func_index)
    new = 'MEMORY_INIT'
    __replace_callname(self, [func_index, new])

    # Rename first function to GLOBAL_INIT
    func_index = 0
    matched.append(func_index)
    new = 'GLOBAL_INIT'
    __replace_callname(self, [func_index, new])

    # Rename second to last function to PLC_PRG (superloop main)
    func_index = num_funcs - 2
    matched.append(func_index)
    new = 'PLC_PRG'
    __replace_callname(self, [func_index, new])

    # Disassembly of INIT_1
    init_1 = '0dc0a0e100582de90cb0a0e104102de50c109fe50021a0e1020091e704109de400a81be9'
    # Disassembly of PROCESS_ID    
    process_ID = '0dc0a0e100582de90cb0a0e100009fe500a81be9'
    # Disassembly of INIT_2
    init_2 = '0dc0a0e100582de90cb0a0e100a81be9'
    
    # Search for matches of BOTH main and init
    for func_index, func in enumerate(prg.Functions[:-2]):
        # Match main functions
        hash_match_main = filter(lambda signature: signature['hash'] == func.hash, main_sign)
        # Match the previous function as the INIT for matched main
        hash_match_init = filter(lambda signature: signature['hash'] == prg.Functions[func_index+1].hash, init_sign)
        # If both match then BINGO! <pats self on the back>
        if hash_match_main and hash_match_init:
            matched.append(func_index)
            matched.append(func_index + 1)
            print('Hashmatch module found function {} at 0x{:x}'.format(hash_match_main[0]['name'], prg.Functions[func_index].start))
            __replace_callname(self, [func_index, hash_match_main[0]['name'], hash_match_main[0]['lib']])
            __replace_callname(self, [func_index+1, hash_match_init[0]['name']])
        # Rename DEBUG HANDLER function
        elif 'SysDebugHandler' in func.calls:
            matched.append(func_index)
            __replace_callname(self, [func_index, 'SYSDEBUG'])
        elif ''.join([x[28:36] for x in prg.Functions[func_index].disasm[:-1]]) == init_1:
            matched.append(func_index)
            __replace_callname(self, [func_index, 'SUB_1'])
        elif ''.join([x[28:36] for x in prg.Functions[func_index].disasm[:-1]]) == process_ID:
            matched.append(func_index)
            __replace_callname(self, [func_index, 'PROCESS_ID'])
        elif ''.join([x[28:36] for x in prg.Functions[func_index].disasm[:-1]]) == init_2:
            matched.append(func_index)
            __replace_callname(self, [func_index, 'SUB_2'])
    
    # Common structure is 0:GLOBAL_INIT, 1: INIT_1, 2: PROCESS_ID, 3: INIT_3, 4: DEBUG_HANDLER
    # Match that if it isn't already matched
    if prg.Functions[4].name == 'DEBUG_HANDLER':
        if prg.Functions[1].name != 'INIT_1':
            __replace_callname(self, [1, 'maybe_INIT_1'])
        if prg.Functions[2].name != 'PROCESS_ID':
            __replace_callname(self, [2, 'maybe_PROCESS_ID'])
        if prg.Functions[3].name != 'INIT_2':
            __replace_callname(self, [3, 'maybe_INIT_2'])

    # Search for maybe matches where only main or only init match
    not_matched = [x for x in range(num_funcs) if x not in matched]
    for func_index in not_matched:
        func = prg.Functions[func_index]
        # Match MAIN functions
        hash_match_main = filter(lambda signature: signature['hash'] == func.hash, main_sign)
        if hash_match_main:
            matched.append(func_index)
            # Construct new_name
            new_name = 'maybe_' + hash_match_main[0]['name']
            for i in hash_match_main[1:]:
                new_name += ' or maybe_' + i['name']
            __replace_callname(self, [func_index, new_name])
            print('Hashmatch module (MAY HAVE) found function {} at 0x{:x}'.format(new_name, prg.Functions[func_index].start))
        
        # Match INIT functions
        hash_match_init = filter(lambda signature: signature['hash'] == func.hash, init_sign)
        if hash_match_init:
            matched.append(func_index)
            new_name = 'maybe_' + hash_match_init[0]['name']
            for i in hash_match_init[1:]:
                new_name += ' or maybe_' + i['name']
            __replace_callname(self, [func_index, new_name])
            print('Hashmatch module (MAY HAVE) found function {} at 0x{:x}'.format(new_name, prg.Functions[func_index].start))

    return 0

def __replace_callname(self, args):
    """
    Replace name of function (also fixing calls from other functions)
    """
    prg = self.prg
    func_index = args[0]
    # Old name
    old = prg.Functions[func_index].name
    #New name
    new = args[1]
    prg.Functions[func_index].name = new
    if len(args) > 2:
        lib = args[2]
        prg.Functions[func_index].lib = lib
    # Replace value in stat libs
    if old in prg.statlibs_dict.values():
        a = prg.statlibs_dict.keys()[prg.statlibs_dict.values().index(old)]
        prg.statlibs_dict[a] = new
    # Iterate over Fuctions to fix calls to the new name
    for func in prg.Functions:
        for call in func.calls.keys():
            if call == old:
                func.disasm = [x.replace('call to {}'.format(old), 'call to {}'.format(new)) for x in func.disasm]
                # func.calls.remove(old)
                # func.calls.append(new)
                func.calls[new] = func.calls.pop(old)
    return 0