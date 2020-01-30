#!/usr/bin/env python

#
# This script is a collection of some useful heap profiling functions
#     based on core_analyzer
#
import argparse
import traceback
import json
from collections import deque

try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

type_code_des = {
  gdb.TYPE_CODE_PTR: 'gdb.TYPE_CODE_PTR',
  gdb.TYPE_CODE_ARRAY: 'gdb.TYPE_CODE_ARRAY',
  gdb.TYPE_CODE_STRUCT: 'gdb.TYPE_CODE_STRUCT',
  gdb.TYPE_CODE_UNION: 'gdb.TYPE_CODE_UNION',
  gdb.TYPE_CODE_ENUM: 'gdb.TYPE_CODE_ENUM',
  gdb.TYPE_CODE_FLAGS: 'gdb.TYPE_CODE_FLAGS',
  gdb.TYPE_CODE_FUNC: 'gdb.TYPE_CODE_FUNC',
  gdb.TYPE_CODE_FLT: 'gdb.TYPE_CODE_FLT',
  gdb.TYPE_CODE_VOID: 'gdb.TYPE_CODE_VOID',
  gdb.TYPE_CODE_RANGE: 'gdb.TYPE_CODE_RANGE',
  gdb.TYPE_CODE_STRING: 'gdb.TYPE_CODE_STRING',
  gdb.TYPE_CODE_BITSTRING: 'gdb.TYPE_CODE_BITSTRING',
  gdb.TYPE_CODE_ERROR: 'gdb.TYPE_CODE_ERROR',
  gdb.TYPE_CODE_METHOD: 'gdb.TYPE_CODE_METHOD',
  gdb.TYPE_CODE_METHODPTR: 'gdb.TYPE_CODE_METHODPTR',
  gdb.TYPE_CODE_MEMBERPTR: 'gdb.TYPE_CODE_MEMBERPTR',
  gdb.TYPE_CODE_REF: 'gdb.TYPE_CODE_REF',
  gdb.TYPE_CODE_CHAR: 'gdb.TYPE_CODE_CHAR',
  gdb.TYPE_CODE_BOOL: 'gdb.TYPE_CODE_BOOL',
  gdb.TYPE_CODE_COMPLEX: 'gdb.TYPE_CODE_COMPLEX',
  gdb.TYPE_CODE_TYPEDEF: 'gdb.TYPE_CODE_TYPEDEF',
  gdb.TYPE_CODE_NAMESPACE: 'gdb.TYPE_CODE_NAMESPACE',
  gdb.TYPE_CODE_DECFLOAT: 'gdb.TYPE_CODE_DECFLOAT',
  gdb.TYPE_CODE_INTERNAL_FUNCTION: 'gdb.TYPE_CODE_INTERNAL_FUNCTION',
}

def heap_usage_value(name, value, blk_addrs):
    unique_value_addrs = set()
    values = deque()
    values.append((name, value))
    size = 0
    count = 0

    # Traverse all nested data members of the value (DFS)
    while values:
        (name, value) = values.pop()
        #print("Evaluate value: " + name)
        if value is None or value.is_optimized_out:
            continue
        parent_addr = None
        if value.address:
            parent_addr = long(value.address)
            if parent_addr in unique_value_addrs:
                #print("Value is repeated: " + name)
                continue
            unique_value_addrs.add(parent_addr)
        '''
        Given a gdb.Value object, return the aggregated heap memory usage reachable through it
        '''
        type = gdb.types.get_basic_type(value.type)
        if type.code == gdb.TYPE_CODE_PTR:  # what about gdb.TYPE_CODE_REF?
            if type is not value.dynamic_type:
                type = value.dynamic_type
                value = value.cast(type)
            addr = long(value)
            #print("pointer value: " + hex(addr))
            blk = gdb.heap_block(addr)
            if blk and blk.inuse and (blk.address not in blk_addrs):
                blk_addrs.add(blk.address)
                size += blk.size
                count += 1
                #print("heap block " + hex(blk.address) + " size=" + str(blk.size))
                target_type = type.target()
                if target_type.sizeof >= 8:
                    v = value.referenced_value()
                    values.append(("*(" + name + ")", v))
        elif type.code == gdb.TYPE_CODE_ARRAY:
            istart, iend = type.range()
            #ptr_to_elt_type = type.target().target().pointer()
            #ptr_to_first = value.cast(ptr_to_elt_type)
            for i in range(istart, iend+1):
                v = value[i]
                if parent_addr and parent_addr == long(v.address):
                    unique_value_addrs.discard(parent_addr)
                values.append((name + '[' + str(i) + ']', v))
        elif type.code == gdb.TYPE_CODE_STRUCT:
            fields = type.fields()
            #fieldnames = []
            #for m in fields:
            #    fieldnames.append(m.name)
            #print(str(fieldnames))
            for m in fields:
                if not hasattr(m, "type"):
                    print(name + "[" + m.name + "] has no type")
                    continue
                #print("Extract field value: " + name + "[" + str(m.name) + "]")
                if m.is_base_class:
                    memval = value.cast(m.type)
                else:
                    memval = value[m]
                if memval is None or memval.address is None:
                    #print(name + "[" + m.name + "] has no value")
                    continue
                mtype = m.type
                if mtype.sizeof >= 8 \
                    and (mtype.code == gdb.TYPE_CODE_PTR \
                        or mtype.code == gdb.TYPE_CODE_REF \
                        #or mtype.code == gdb.TYPE_CODE_RVALUE_REF \
                        or mtype.code == gdb.TYPE_CODE_ARRAY \
                        or mtype.code == gdb.TYPE_CODE_STRUCT \
                        or mtype.code == gdb.TYPE_CODE_UNION \
                        or mtype.code == gdb.TYPE_CODE_TYPEDEF):
                    #print(name + "[" + member.name + "]" + " type.code=" + type_code_des[mtype.code] \
                    #    + " type.name=" + str(mtype.tag))
                    if parent_addr and parent_addr == long(memval.address):
                        # first field of a struct has the same value.address as
                        # the struct itself, we have to remove it from the set
                        # TODO ensure the first data member is NOT a pointer and points
                        #      to the struct itself.
                        unique_value_addrs.discard(parent_addr)
                    values.append((name + '[' + str(m.name) + ']', memval))

    return size, count

def symbol2value(symbol, frame=None):
    '''
    Given a gdb.Symbol object, return the corresponding gdb.Value object
    '''
    if not symbol.is_valid():
        return None
    try:
        if frame:
            return symbol.value(frame)
        else:
            return symbol.value()
    except Exception as e:
        print("Failed symbol.value: " + str(e))
        return None

def get_typename(type, expr):
    type_name = type.tag
    if not type_name:
        try:
            type_name = gdb.execute("whatis " + expr, False, True).rstrip()
            # remove leading substring 'type = '
            type_name = type_name[7:]
        except RuntimeError as e:
            #print("RuntimeError: " + str(e))
            #type_name = "unknown"
            pass
    return type_name

class PrintTopVariableCommand(gdb.Command):
    '''
    A GDB command that print variables with most memory heap usage
    '''
    _command = "topvars"
    _cfthreadno = 0
    _show_count = 20
    _verbose = False

    def __init__(self):
        gdb.Command.__init__(self, self._command, gdb.COMMAND_STACK)

    def calc_input_vars(self, argument):
        tokens = argument.split()
        if not len(tokens):
            print("Invalid argument: [" + argument + "]")
            return
        #parser = argparse.ArgumentParser(description='Expression Parser')
        #parser.add_argument("param", help='parameters')
        #tokens = parser.parse_args(argumenti.split())
        #print(tokens)
        for expr in tokens:
            #print("processing " + expr)
            v = gdb.parse_and_eval(expr)
            if not v:
                #symbol = gdb.lookup_symbol(expr)
                symbol = gdb.lookup_global_symbol(expr, gdb.SYMBOL_VAR_DOMAIN)
                if symbol:
                    v = symbol2value(symbol)
                    if not v:
                        print("symbol2value failed for: " + symbol.name)
                else:
                    print("gdb.lookup_global_symbol failed for: " + expr)
            if v:
                blk_addrs = set()
                sz, cnt = heap_usage_value(expr, v, blk_addrs)
                type = v.type
                type_name = get_typename(type, expr)
                print("expr=" + expr + " type=" + type_name + " size=" + str(type.sizeof) \
                    + " heap=" + str(sz) + " count=" + str(cnt))
            else:
                print("gdb.parse_and_eval failed for: " + expr)

    def calc_all_vars(self):
        unique_value_addrs = set()
        blk_addrs = set()
        gvs = []
        all_results = []
        total_bytes = 0
        total_count = 0
        # Remember previous selected thread (may be None)
        orig_thread = gdb.selected_thread()
        all_threads = gdb.inferiors()[0].threads()
        num_threads = len(all_threads)
        print("There are totally " + str(num_threads) + " threads")
        # Traverse all threads
        for thread in gdb.inferiors()[0].threads():
            #if thread.num != 4:
            #    continue
            # Switch to current thread
            thread.switch()
            print("Thread " + str(thread.num))
            # Traverse all frames starting with the innermost
            frame = gdb.newest_frame()
            i = 0
            while frame:
                try:
                    frame.select()
                    fname = frame.name()
                    if not fname:
                        fname = "??"
                    print("frame [" + str(i) + "] " + fname)
                    symbol_names = set()
                    # Traverse all blocks
                    try:
                        # this method may throw if there is no debugging info in the block
                        block = frame.block()
                    except Exception:
                        block = None
                    # Traverse all syntactic blocks
                    while block:
                        # Traverse all symbols in the block
                        for symbol in block:
                            #print("symbol " + symbol.name)
                            # Ignore other symbols, for example, argument, except variables
                            if not symbol.is_variable:
                                #print("symbol [" + symbol.name + "]" + " is not var or arg")
                                continue
                            if symbol.name in symbol_names:
                                continue
                            symbol_names.add(symbol.name)
                            #if not symbol.is_valid():
                            #    continue
                            #if symbol.addr_class == gdb.SYMBOL_LOC_OPTIMIZED_OUT:
                            #    continue
                            #if not symbol.type:
                            #    continue
                            # Global symbols are processed later
                            if block.is_global or block.is_static:
                                v = symbol2value(symbol, frame)
                                if v and v.address:
                                    addr = long(v.address)
                                    if addr not in unique_value_addrs:
                                        unique_value_addrs.add(addr)
                                        gvs.append((symbol, v))
                                continue
                            # Local variable
                            #print("Processing symbol " + symbol.name)
                            type = symbol.type
                            type_name = get_typename(type, symbol.name)
                            if not type_name:
                                #print("symbol " + symbol.name + " has no type name")
                                continue
                            # Convert to gdb.Value
                            v = symbol2value(symbol, frame)
                            if v is None:
                                #if symbol.name == "this":
                                #    print("symbol2value fails for symbol " + symbol.name)
                                continue
                            # Skip variable that has been processed previously
                            # register variable has no address, however.
                            if v.address is not None:
                                addr = long(v.address)
                                if addr in unique_value_addrs:
                                    continue
                                unique_value_addrs.add(addr)
                            sz, cnt = heap_usage_value(symbol.name, v, blk_addrs)
                            if sz and cnt:
                                id = "thread " + str(thread.num) + " frame [" + str(i) + "] " + symbol.name
                                all_results.append((id, sz, cnt))
                                total_bytes += sz
                                total_count += cnt
                            if self._verbose:
                                print("\t" + "symbol=" + symbol.name + " type=" + type_name \
                                    + " size=" + str(type.sizeof) \
                                    + " heap=" + str(sz) + " count=" + str(cnt))
                        block = block.superblock
                except Exception as e:
                    print("Exception: " + str(e))
                    traceback.print_exc()
                    pass
                frame = frame.older()
                i += 1
            print("") #End of one thread
        # Restore context
        orig_thread.switch() #End of all threads

        # print globals after all threads are visited
        print("")
        print("Global Vars")
        sorted_gvs = sorted(gvs, key=lambda gv: gv[0].symtab.filename)
        scopes = set()
        for (symbol, v) in sorted_gvs:
            type = symbol.type
            type_name = get_typename(type, symbol.name)
            if not type_name:
                #print("get_typename failed for: " + symbol.name)
                continue
            if symbol.symtab.filename not in scopes:
                # print file name once
                scopes.add(symbol.symtab.filename)
                print("\t" + symbol.symtab.filename + ":")
            #print("processing " + symbol.name)
            sz, cnt = heap_usage_value(symbol.name, v, blk_addrs)
            if sz and cnt:
                id = symbol.symtab.filename + " " + symbol.name
                all_results.append((id, sz, cnt))
                total_bytes += sz
                total_count += cnt
            if self._verbose:
                print("\t\t" + "symbol=" + symbol.name + " type=" + type_name \
                    + " size=" + str(type.sizeof) \
                    + " heap=" + str(sz) + " count=" + str(cnt))
        # Sort results by top n size and cnt
        sorted_results = sorted(all_results, key=lambda elem: elem[1], reverse = True)
        i = 0
        print("===================================================")
        for var in sorted_results:
            print("[" + str(i) + "] " + var[0] + " size=" + str(var[1]) + " count=" + str(var[2]))
            i += 1
            if i > self._show_count:
                break
        # Print summary
        print("Total heap usage: " + str(total_bytes) + " count: " + str(total_count))

    def invoke(self, argument, from_tty):
        print("Find variables with most memory consumption")

        try:
            if argument:
                # Evaluate specified expressions
                self.calc_input_vars(argument)
            else:
                # Traverse all local/global variables
                self.calc_all_vars()
        except Exception as e:
            print("Exception: " + str(e))
            traceback.print_exc()

PrintTopVariableCommand()

def topblocks(n=10):
    blocks = {}
    blk=gdb.heap_walk(0)
    while blk:
        if blk.inuse:
            if blk.size in blocks:
                blocks[blk.size] += 1
            else:
                blocks[blk.size] = 1
        blk=gdb.heap_walk(blk)
    #Print stats
    total_inuse_count = 0
    total_inuse_bytes = 0
    for blkSz in blocks:
        total_inuse_count += blocks[blkSz]
        total_inuse_bytes += blkSz * blocks[blkSz]
    print "Total inuse blocks: ", total_inuse_count, " total bytes: ", \
        total_inuse_bytes, " number of size classes: ", len(blocks)
    #Top n blocks by size
    print "Top ", n, " blocks by size"
    pn = n
    for sz in sorted(blocks.keys(), reverse = True):
        count = blocks[sz]
        while count > 0 and pn > 0:
            print "\t", sz
            pn -= 1
            count -= 1
        if pn == 0:
            break
    #Top n size class by count
    print "Top ", n, " block sizes by count"
    pn = n
    for key, value in sorted(blocks.items(), key=lambda kv: kv[1], reverse=True):
        print "\t size ", key, " count: ", value
        pn -= 1
        if pn == 0:
            break
    print ""

def heapwalk(addr=0,n=0xffffffff):
    total=0
    total_inuse=0
    total_free=0
    total_inuse_bytes=0
    total_free_bytes=0
    blk=gdb.heap_walk(addr)

    while blk:
        total=total+1
        if blk.inuse:
            total_inuse=total_inuse+1
            total_inuse_bytes=total_inuse_bytes+blk.size
        else:
            total_free=total_free+1
            total_free_bytes=total_free_bytes+blk.size

        print "[", total, "] ", blk
        if n!=0 and total>=n:
            break

        blk=gdb.heap_walk(blk)

    print "Total ", total_inuse, " inuse blocks of ", total_inuse_bytes, " bytes"
    print "Total ", total_free, " free blocks of ", total_free_bytes, " bytes"
