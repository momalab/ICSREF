#!/usr/bin/env python

__author__ = 'Tasos Keliris'

import pygraphviz as pgv
import os

def graphbuilder(self, args):
    """Create visualization of program callgraph using graphviz
        
    No args

    :Example:
    
        reversing\@icsref:$ graphbuilder
    
    """
    self.do_cleanup(None)
    try:
        prg = self.prg
    except AttributeError:
        print('Error: You need to first load or analyze a program')
        return 0

    name = prg.name
    functions = prg.Functions
    for fun in functions:
        fun_f = os.path.join('results', prg.name, fun.name + '.disasm')
        with open(fun_f, 'w') as f:
            f.write('\n'.join(fun.disasm))
    G=pgv.AGraph(strict = True, directed = True, ranksep='2')
    G.node_attr['shape']='box'
    for fun in functions:
        G.add_node(fun.name, URL='{}.disasm'.format(fun.name))
    for fun in functions:
        for lib in fun.calls.keys():
            if lib in prg.statlibs_dict.values():
                G.add_edge(fun.name, lib, color='blue', label=fun.calls[lib])
            else:
                G.add_edge(fun.name, lib, color='red', label=fun.calls[lib])
    G.layout(prog='dot')
    graph_f = 'graph_{}.svg'.format(name)
    G.draw(graph_f)
    os.rename(graph_f, os.path.join('results', prg.name, graph_f))
    print('Generated graph_{}.svg'.format(name))
    return 0