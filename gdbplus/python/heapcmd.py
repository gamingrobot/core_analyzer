#!/usr/bin/env python

#
# This script is a collection of some useful heap profiling functions
#     based on core_analyzer
#
import argparse
import traceback
import json
try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

type_code_des = {
  gdb.TYPE_CODE_PTR: 'gdb.TYPE_CODE_PTR',
  gdb.TYPE_CODE_PTR: 'gdb.TYPE_CODE_ARRAY',
  gdb.TYPE_CODE_STRUCT: 'gdb.TYPE_CODE_STRUCT',
  gdb.TYPE_CODE_UNION: 'gdb.TYPE_CODE_UNION',
  gdb.TYPE_CODE_ENUM: 'gdb.TYPE_CODE_ENUM',
  gdb.TYPE_CODE_FLAGS: 'gdb.TYPE_CODE_FLAGS',
  gdb.TYPE_CODE_FUNC: 'gdb.TYPE_CODE_FUNC',
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

def heap_usage_value(name, value, visited_values):
    if value is None or not value.address:
        return 0, 0
    val_addr = long(value.address)
    if val_addr in visited_values:
        return 0, 0
    visited_values.add(val_addr)
    '''
    Given a gdb.Value object, return the aggregated heap memory usage reachable by this variable
    '''
    size = 0
    count = 0

    type = gdb.types.get_basic_type(value.type)
    if type.code == gdb.TYPE_CODE_PTR:
        addr = long(value)
        #print(hex(addr))
        blk = gdb.heap_block(addr)
        if blk and blk.inuse:
            size += blk.size
            count += 1
            #print("heap block " + hex(blk.address) + " size=" + str(blk.size))
            target_type = type.target()
            if target_type.sizeof >= 8:
                v = value.referenced_value()
                sz, cnt = heap_usage_value(name + '->', v, visited_values)
                size += sz
                count += cnt
    elif type.code == gdb.TYPE_CODE_ARRAY:
        istart, iend = type.range()
        #ptr_to_elt_type = type.target().target().pointer()
        #ptr_to_first = value.cast(ptr_to_elt_type)
        for i in range(istart, iend+1):
            v = value[i]
            if val_addr == long(v.address):
                visited_values.discard(val_addr)
            sz, cnt = heap_usage_value(name + '[' + str(i) + ']', v, visited_values)
            size += sz
            count += cnt
    elif type.code == gdb.TYPE_CODE_STRUCT:
        fields = type.fields()
        #fieldnames = []
        #for m in fields:
        #    fieldnames.append(m.name)
        #print(str(fieldnames))
        for member in fields:
            if not hasattr(member, "type"):
                continue
            memval = value[member]
            if not memval or not memval.address:
                continue
            mtype = member.type
            if mtype.sizeof >= 8 \
                and (mtype.code == gdb.TYPE_CODE_PTR \
                    or mtype.code == gdb.TYPE_CODE_REF \
                    #or mtype.code == gdb.TYPE_CODE_RVALUE_REF \
                    or mtype.code == gdb.TYPE_CODE_ARRAY \
                    or mtype.code == gdb.TYPE_CODE_STRUCT \
                    or mtype.code == gdb.TYPE_CODE_UNION \
                    or mtype.code == gdb.TYPE_CODE_TYPEDEF):
                #print(name + "[" + member.name + "]" + " type.code=" + type_code_des[mtype.code])
                if val_addr == long(memval.address):
                    # first field of a struct has the same value.address as
                    # the struct itself, we have to remove it from the set
                    # TODO ensure the first data member is NOT a pointer and points
                    #      to the struct itself.
                    visited_values.discard(val_addr)
                sz, cnt = heap_usage_value(name + '[' + member.name + ']', memval, visited_values)
                size += sz
                count += cnt

    return size, count

def symbol2value(symbol, frame=None):
    '''
    Given a gdb.Symbol object, return the aggregated heap memory usage reachable by this variable
    '''
    if not symbol.is_variable or not symbol.is_valid():
        return None
    try:
        return symbol.value(frame)
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
    
    def __init__(self):
        gdb.Command.__init__(self, self._command, gdb.COMMAND_STACK)

    def calc_input_vars(self, argument):
        tokens = argument.split()
        if not len(tokens):
            print("Invalid argument: [" + argument + "]")
            return
        #parser = argparse.ArgumentParser(description='Expression Parser')
        #parser.add_argument("param", help='parameters')
        #args = parser.parse_args(tokens)
        #print(tokens)
        for expr in tokens:
            v = gdb.parse_and_eval(expr)
            if v:
                visited_values = set()
                type = v.type
                type_name = get_typename(type, expr)
                sz, cnt = heap_usage_value(expr, v,visited_values)
                print("expr=" + expr + " type=" + type_name + " size=" + str(type.sizeof) \
                    + " heap=" + str(sz) + " count=" + str(cnt))

    def calc_all_vars(self):
        gv_addrs = set()
        gvs = []
        # Preserve previous selected thread (may be None)
        orig_thread = gdb.selected_thread()
        all_threads = gdb.inferiors()[0].threads()
        num_threads = len(all_threads)
        print("There are totally " + str(num_threads) + " threads")
        # Traverse all threads
        for thread in gdb.inferiors()[0].threads():
            #if thread.num != 586:
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
                    # Traverse all blocks
                    try:
                        # this method may throw if there is no debugging info in the block
                        block = frame.block()
                    except Exception:
                        block = None
                    while block:
                        # Traverse all symbols in the block
                        for symbol in block:
                            # Ignore other symbols except variables
                            if not symbol.is_variable:
                                continue
                            #if not symbol.is_valid():
                            #    continue
                            #if symbol.addr_class == gdb.SYMBOL_LOC_OPTIMIZED_OUT:
                            #    continue
                            #if not symbol.type:
                            #    continue
                            # Global symbols are processed later
                            elif block.is_global or block.is_static:
                                v = symbol2value(symbol, frame)
                                if v is not None and v.address:
                                    addr = long(v.address)
                                    if addr not in gv_addrs:
                                        gv_addrs.add(addr)
                                        gvs.append((symbol, v))
                                continue
                            # Local variable
                            #print("symbol " + symbol.name)
                            # Old gdb.Type doesn't have attribute 'name'
                            type = symbol.type
                            type_name = get_typename(type, symbol.name)
                            if not type_name:
                                continue
                            # Convert to gdb.Value
                            v = symbol2value(symbol, frame)
                            visited_values = set()
                            sz, cnt = heap_usage_value(symbol.name, v, visited_values)
                            print("\t" + "symbol=" + symbol.name + " type=" + type_name + " size=" + str(type.sizeof) \
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
        for (symbol, value) in sorted_gvs:
            type = symbol.type
            type_name = get_typename(type, symbol.name)
            if symbol.symtab.filename not in scopes:
                scopes.add(symbol.symtab.filename)
                print("\t" + symbol.symtab.filename + ":")
            visited_values = set()
            sz, cnt = heap_usage_value(symbol.name, value, visited_values)
            if sz is None or cnt is None:
                print("\t\t" + "symbol=" + symbol.name + " type=" + type_name + " FAIL")
                continue
            print("\t\t" + "symbol=" + symbol.name + " type=" + type_name + " size=" + str(type.sizeof) \
                + " heap=" + str(sz) + " count=" + str(cnt))

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
