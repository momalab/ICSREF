#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import os

def analytics(self, args):
    """
    Print analytics of program

    No args

    :Example:
    
        reversing\@icsref:$ analytics

    """
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program')
        return 0

    path = os.path.join('results', prg.name)
    try: 
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise
    txt_f = open(os.path.join(path, '{}.analytics'.format(prg.name)), 'w')

    totals = {}

    for fun in prg.Functions:
        for call in fun.calls:
            if call not in prg.statlibs_dict.values():
                print('{} --|{}|--> {}'.format(fun.name, fun.calls[call], call))
                txt_f.write('{} --|{}|--> {}\n'.format(fun.name, fun.calls[call], call))
            else:
                print('{} --|{}|--> {} <=> {} --|{}|--> {}'.format(fun.name, fun.calls[call], call, fun.hash, fun.calls[call], [x.hash for x in prg.Functions if x.name == call][0]))
                txt_f.write('{} --|{}|--> {} <=> {} --|{}|--> {}\n'.format(fun.name, fun.calls[call], call, fun.hash, fun.calls[call], [x.hash for x in prg.Functions if x.name == call][0]))
            if call not in totals.keys():
                totals[call] = fun.calls[call]
            else:
                totals[call] += fun.calls[call]
        if fun.calls:
            print('')
            txt_f.write('\n')
    print('\nTotals:')
    for key in totals:
        if key in prg.statlibs_dict.values():
            print('{} calls to {} <=> {}'.format(totals[key], key, [x.hash for x in prg.Functions if x.name == key][0]))
            txt_f.write('{} calls to {} <=> {}\n'.format(totals[key], key, [x.hash for x in prg.Functions if x.name == key][0]))
        else:
            print('{} calls to {}'.format(totals[key], key))
            txt_f.write('{} calls to {}\n'.format(totals[key], key))
    txt_f.close()

    return 0
