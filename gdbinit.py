# USAGE:
#     cd /path/to/dump-seccomp
#     make
#     gdb TARGET_PROGRAM -ex 'source gdbinit.py' -ex 'run CMDLINE_ARGS'
#     [press CTRL+C after all prctl calls have been hit]
#     cat seccomp.log
from __future__ import print_function
import gdb
import inspect
import os
import re
import struct
import subprocess
import traceback

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_STRICT = 1
SECCOMP_MODE_FILTER = 2

def get_bpf_dbg_path():
    script_path = inspect.getfile(inspect.currentframe())
    return os.path.join(os.path.dirname(os.path.abspath(script_path)), 'bpf_dbg')

def execute(cmd):
    return gdb.execute(cmd, False, True)

def get_arch():
    out = execute('maintenance info sections ?')
    m = re.search(r'file type ([^\.]+)', out)
    assert m
    arch = m.group(1)
    return arch

def get_registers():
    regs = {}
    for line in execute('info registers').splitlines():
        parts = line.split()
        regs[parts[0]] = int(parts[1], 16)
    return regs

arch = get_arch()
if 'x86-64' in arch:
    bits = 64
elif 'x86' in arch:
    bits = 32
else:
    raise Exception('Unsupported platform: ' + arch)

logfile = 'seccomp.log'
f = open(logfile, 'w')
print('Writing to logfile %s' % logfile)
def log(s):
    print(s)
    print(s, file=f)
    f.flush()

def read(start, size):
    out = execute('x/{}bx {}'.format(size, start))
    res = []
    for line in out.splitlines():
        res += [int(x, 16) for x in line.split(':')[1].split()]
    assert len(res) == size
    return bytes(bytearray(res))

def disassemble(blocks):
    bpf_dbg_str = b'%d' % len(blocks)
    for b in blocks:
        bpf_dbg_str += b',%d %d %d %d' % b
    p = subprocess.Popen([get_bpf_dbg_path()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(b'load bpf %s\ndisassemble\n' % bpf_dbg_str)
    if err:
        return 'Error: %s' % err.decode('utf-8')
    else:
        return out.decode('utf-8').split('>')[-2].split('disassemble\n')[1]

def dump_filters(fprog_addr):
    fmt = {64: '<HxxxxxxQ', 32:'<HxxI'}[bits]
    num, filter_ary = struct.unpack(
            fmt, read(fprog_addr, struct.calcsize(fmt)))
    log('  fprog @ %016x'% fprog_addr)
    log('  %d filters @ %016x' % (num, filter_ary))
    block_fmt = '<HBBI'
    block_sz = struct.calcsize(block_fmt)
    blocks = []
    for i in range(num):
        block = struct.unpack(block_fmt, read(filter_ary + i*block_sz, block_sz))
        blocks.append(block)
    log('  Disassembly:')
    log('\n'.join('     %s' % line for line in disassemble(blocks).splitlines()))

memo = set()
def stop_handler(evt):
    try:
        # don't catch ^C/^D
        if isinstance(evt, gdb.SignalEvent):
            return
        #if bits == 64:
            #ins = execute('x/1i $rip-2')
            #if not re.search(r'\ssyscall[\s\n]*$', ins):
                #return
        #else:
            #raise NotImplementedError('32 bit not implemented')
        regs = get_registers()
        #syscall_num = regs['rax'] if bits == 64 else regs['eax']
        if bits == 64:
            arg0 = regs['rdi']
            arg1 = regs['rsi']
            arg2 = regs['rdx']
        else:
            arg0 = regs['ebx']
            arg1 = regs['ecx']
            arg2 = regs['edx']
        args = (arg0, arg1, arg2)
        if args not in memo:
            memo.add(args)
            if arg0 == PR_SET_NO_NEW_PRIVS:
                log('prctl(PR_SET_NO_NEW_PRIVS)')
            elif arg0 == PR_SET_SECCOMP:
                if arg1 == SECCOMP_MODE_STRICT:
                    log('prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)')
                elif arg1 == SECCOMP_MODE_FILTER:
                    log('prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)')
                    dump_filters(arg2)
                else:
                    raise Exception('Unknown second argument to prctl')
        gdb.execute('c')
    except:
        traceback.print_exc()

execute('catch syscall prctl')
gdb.events.stop.connect(stop_handler)
