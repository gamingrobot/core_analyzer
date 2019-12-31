#!/usr/bin/env python

#
# This script is a collection of some useful heap profiling functions
#     based on core_analyzer
#

try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

class PrintTopVariableCommand(gdb.Command):
    '''
    A GDB command that print variables with most memory usage
    '''
    _command = "topvars"
    _cfthreadno = 0
    
    def __init__(self):
        gdb.Command.__init__(self, self._command, gdb.COMMAND_STACK)

    def invoke(self, argument, from_tty):
        gdb.write("Find variables with most memory consumption\n")    
        # Preserve previous selected thread (may be None)
        orig_thread = gdb.selected_thread()
        all_threads = gdb.inferiors()[0].threads()
        num_threads = len(all_threads)
        gdb.write("There are totally %s threads\n" % num_threads)
        for thread in gdb.inferiors()[0].threads():
            # Switch to current thread
            thread.switch()
            gdb.write("Thread %d\n" % (thread.num))
            # Start with the innermost frame
            frame = gdb.newest_frame()
            i = 0
            while frame:
                try:
                    frame.select()
                    gdb.write("frame %d\n" % (i))
                    block = frame.block()
                    while block:
                        #if block.is_global:
                        #    gdb.write("global\n")
                        #if block.is_static:
                        #    gdb.write("static\n")
                        for symbol in block:
                            # Old gdb.Type doesn't have attribute 'name'
                            type_name = symbol.type.tag
                            if not type_name:
                                type_name = gdb.execute("whatis %s" % symbol.name, False, True).rstrip()
                                # remove leading substring 'type = '
                                type_name = type_name[7:]
                            if symbol.is_variable:
                                gdb.write("\tsymbol='%s' type='%s' size='??'" % (symbol.name, type_name))
                                #if symbol.is_argument:
                                #    gdb.write(" argument")
                                #if symbol.is_variable:
                                #    gdb.write(" variable")
                                gdb.write("\n")
                        block = block.superblock
                except Exception as e:
                    gdb.write("Exception: %s\n" % str(e))
                frame = frame.older()
                i += 1

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
