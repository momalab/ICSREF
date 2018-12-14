#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import os

def cleanup(self, args):
    """
    Remove .disasm and .svg files created by graphbuilder
    
    No args

    :Example:
    
        reversing\@icsref:$ cleanup
    
    """
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program')
        return 0

    for dirname, dirnames, filenames in os.walk(os.path.join(os.getcwd(), 'results', prg.name)):
        for i in filenames:
            if i.endswith('.disasm'):
                os.remove(os.path.join(dirname, i))
            if i.endswith('.svg'):
                os.remove(os.path.join(dirname, i))
            if i.endswith('.PRG'):
                os.remove(os.path.join(dirname, i))   
            if i.endswith('.CHK'):
                os.remove(os.path.join(dirname, i))   
            if i == 'analytics.txt':
                os.remove(os.path.join(dirname, i))
    print('Cleanup complete')
    return 0