import struct
import subprocess
import os
import inspect

def get_bpf_dbg_path():
    script_path = os.path.abspath(
            os.path.expanduser(
                inspect.getfile(inspect.currentframe())))
    return os.path.join(os.path.dirname(script_path),
            'bpf_dbg')

def disassemble(blocks):
    bpf_dbg_str = [b'%d' % len(blocks)]
    for b in blocks:
        bpf_dbg_str.append(b',%d %d %d %d' % b)
    bpf_dbg_str = b''.join(bpf_dbg_str)
    p = subprocess.Popen([get_bpf_dbg_path()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(b'load bpf %s\ndisassemble\n' % bpf_dbg_str)
    if err:
        return 'Error: %s' % err.decode('utf-8')
    else:
        return out.decode('utf-8').split('>')[-2].split('disassemble\n')[1]

block_fmt = '<HBBI'
block_sz = struct.calcsize(block_fmt)

def disassemble_binary(data):
    blocks = []
    assert len(data) % block_sz == 0
    for i in range(0, len(data), block_sz):
        blocks.append(struct.unpack(block_fmt, data[i:i+block_sz]))
    return disassemble(blocks)
