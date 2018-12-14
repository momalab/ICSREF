#!/usr/bin/env python

__author__ = 'Tasos Keliris'
__docformat__ = 'reStructuredText'

import sys
sys.dont_write_bytecode=True

from shutil import copyfile
from cmd2 import Cmd
import os
import dill
import importlib
import inspect
from PRG_analysis import *
from timeit import default_timer as timer

class icsrefPrompt(Cmd):
    """
    cmd2 prompt class for the interactive console
    """
    def __init__(self):
        Cmd.__init__(self, use_ipython=True)

    def do_load(self, filename):
        """
        Load saved analyzed object from .dat file
            
        :param: filename of .dat file to load

        :Example:

            reversing\@icsref:$ load results/INTEGRAL/INTEGRAL.dat

        """
        if len(filename) == 0 or not os.path.isfile(filename):
            print('Please provide path to a *.dat file')
        elif filename[-4:] != '.dat':
            print('You must provide a .dat file')
        else:
            with open(filename, 'r') as f:
                self.prg = dill.load(f)
            print('Loading of {} finished.'.format(self.prg.name))

            # Create results dir
            path = os.path.join('results', self.prg.name)
            try:
                os.makedirs(path)
            except OSError:
                if not os.path.isdir(path):
                    raise
            # Copy loaded file to results/prg.name path
            new_loc = os.path.join(path, os.path.split(filename)[-1])
            if os.path.abspath(filename) != os.path.abspath(new_loc):
                copyfile(filename, new_loc)

    def do_analyze(self, filename):
        """
        Perform core analysis on PRG file

       :param filename: filename of PRG file to analyze

       :Example:

            reversing\@icsref:$ analyze test/INTEGRAL.PRG

        """
        if len(filename) == 0 or not os.path.isfile(filename):
            print('Please provide path to a *.PRG file')
        elif filename[-4:].upper() != '.PRG':
            print('You must provide a .PRG file')
        else:
            print('Working on {}.'.format(filename))
            start = timer()
            self.prg = Program(filename)
            end = timer()
            print('Analysis of {} finished.'.format(self.prg.name))
            print('Total analysis time: {}'.format(end - start))

    def do_save(self, filename):
        """
        Save analysis to .dat file

        :param filename<optional>: filename to save output of analysis
       
        if no file is provided then filename is analyzed\_<prg.name>.dat
       
        :Example:

            reversing\@icsref:$ save INTEGRAL_new

        """
        if not filename:
            outfile = '{}.dat'.format(self.prg.name + "_analysis")
        else:
            outfile = filename + '.dat'
        dat_f = os.path.join('results', self.prg.name, outfile)
        with open(dat_f, 'w') as f:
            dill.dump(self.prg, f)
        print('Saved {}.'.format(outfile))
        return 0

def console():
    prompt = icsrefPrompt()
    prompt.prompt = 'reversing@icsref:$ '

    # Load banner
    thisdir = os.path.split(__file__)[0]
    banner_f = os.path.join(thisdir, 'data', 'banner')
    __file__
    with open(banner_f, 'r') as f:
        lines = f.readlines()
    banner = ''
    for line in lines:
        banner += line

    # Import modules
    # Assumes the modules follow these conventions:
    # 1) Naming: module_<name>.py
    # 2) Functions: def <name>(self, args) -- this is limiting but meh
    
    # FIX
    sys.path.append(thisdir)
    for i in os.listdir(os.path.join(thisdir, 'modules')):
        if i.startswith('module_') and i.endswith('.py'):
            # Get name without extension
            mod_name = 'modules.' + os.path.splitext(i)[0]
            # Get module
            mod = importlib.import_module(mod_name)
            # Add the methods of mod (ONLY) to icsrefPrompt class as do_<something>
            name_func_tuples = inspect.getmembers(mod, inspect.isfunction)
            name_func_tuples = [t for t in name_func_tuples if inspect.getmodule(t[1]) == mod]
            for fun in name_func_tuples:
                setattr(icsrefPrompt, 'do_{}'.format(fun[0]), fun[1])
    
    # Start cmd module
    prompt.cmdloop(banner)

# Main function
if __name__ == '__main__':
    console()