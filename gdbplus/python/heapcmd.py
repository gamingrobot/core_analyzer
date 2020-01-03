#!/usr/bin/env python

#
# This script is a collection of some useful heap profiling functions
#     based on core_analyzer
#
import json
try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

def heap_usage_value(value):
    if not value:
        return 0
    '''
    Given a gdb.Value object, return the aggregated heap memory usage reachable by this variable
    '''
    size = 0
    count = 0

    #print(value)
    if value.address:
        addr = long(value.address)
        #print("gdb.heap_walk("+str(addr)+")")
        blk = gdb.heap_block(addr)
        if blk and blk.inuse:
            #print("gdb.heap_walk("+str(addr)+") = " + json.dumps(blk))
            size += blk.size

    type = value.type
    if type.code == gdb.TYPE_CODE_PTR:
        v = value.referenced_value()
        return heap_usage_value(v)
    size += type.sizeof
    return size

def symbol2value(symbol, frame=None):
    '''
    Given a gdb.Symbol object, return the aggregated heap memory usage reachable by this variable
    '''
    if not symbol.is_variable or not symbol.is_valid():
        return None
    try:
        value = symbol.value(frame)
    except Exception as e:
        #print("Exception: " + str(e))
        return None
    return value

class PrintTopVariableCommand(gdb.Command):
    '''
    A GDB command that print variables with most memory heap usage
    '''
    _command = "topvars"
    _cfthreadno = 0
    
    def __init__(self):
        gdb.Command.__init__(self, self._command, gdb.COMMAND_STACK)

    def invoke(self, argument, from_tty):
        gv_addrs = set()
        gvs = []
        print("Find variables with most memory consumption")
        # Preserve previous selected thread (may be None)
        orig_thread = gdb.selected_thread()
        all_threads = gdb.inferiors()[0].threads()
        num_threads = len(all_threads)
        print("There are totally " + str(num_threads) + " threads")
        for thread in gdb.inferiors()[0].threads():
            # Switch to current thread
            thread.switch()
            print("Thread " + str(thread.num))
            # Start with the innermost frame
            frame = gdb.newest_frame()
            i = 0
            while frame:
                try:
                    frame.select()
                    print("frame [" + str(i) + "] " + frame.name())
                    block = frame.block()
                    while block:
                        for symbol in block:
                            if not symbol.is_variable:
                                continue
                            elif block.is_global or block.is_static:
                                v = symbol2value(symbol, frame)
                                if v and v.address:
                                    addr = long(v.address)
                                    if addr not in gv_addrs:
                                        gv_addrs.add(addr)
                                        gvs.append((symbol, v))
                                continue
                            # Old gdb.Type doesn't have attribute 'name'
                            type = symbol.type
                            type_name = symbol.type.tag
                            if not type_name:
                                type_name = gdb.execute("whatis %s" % symbol.name, False, True).rstrip()
                                # remove leading substring 'type = '
                                type_name = type_name[7:]
                            v = symbol2value(symbol, frame)
                            print("\t" + "symbol=" + symbol.name + " type=" + type_name + " size=" + str(type.sizeof) \
                                + " heap=" + str(heap_usage_value(v)))
                        block = block.superblock
                except RuntimeError as e:
                    #print("Exception: " + str(e))
                    pass
                frame = frame.older()
                i += 1
            print("") #end of one thread
        # print globals after all threads are visited
        print("")
        print("Global Vars")
        sorted_gvs = sorted(gvs, key=lambda gv: gv[0].symtab.filename)
        scopes = set()
        for (symbol, value) in gvs:
            type = symbol.type
            type_name = symbol.type.tag
            if not type_name:
                type_name = gdb.execute("whatis %s" % symbol.name, False, True).rstrip()
                # remove leading substring 'type = '
                type_name = type_name[7:]
            if symbol.symtab.filename not in scopes:
                scopes.add(symbol.symtab.filename)
                print("\t" + symbol.symtab.filename + ":")
            #v = symbol2value(symbol)
            #if not v:
            #    print("failed to get gdb.value")
            print("\t\t" + "symbol=" + symbol.name + " type=" + type_name + " size=" + str(type.sizeof) \
                + " heap=" + str(heap_usage_value(value)))
        # Restore context
        orig_thread.switch()

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
