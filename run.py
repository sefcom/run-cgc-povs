#!/usr/bin/env python3

import os
import sys
import re
import json
import subprocess
import multiprocessing
import io
import signal
import ctypes
import errno
import traceback


CGC_FLAG_PAGE_ADDRESS = 0x4347C000
PAGE_SIZE = 4096
TYPE_2_DATA = b''.join(e.to_bytes(4, 'little')
                       for e in (CGC_FLAG_PAGE_ADDRESS, PAGE_SIZE, 4))


libc = ctypes.CDLL("libc.so.6")

with open('/usr/include/x86_64-linux-gnu/asm/unistd_64.h') as f:
    SYSCALL_NUM = {
        match[0]: int(match[1])
        for match in re.findall('#define __NR_(\w+) (\d+)', f.read())
    }
    SYSCALL_NAME = {v: k for k, v in SYSCALL_NUM.items()}

with open('/usr/include/x86_64-linux-gnu/sys/ptrace.h') as f:
    PTRACE = {
        match[0]: int(match[1])
        for match in re.findall('PTRACE_(\w+) = (\d+),', f.read())
    }
    ptrace_data = f.read()


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("rax", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("orig_rax", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("cs", ctypes.c_uint64),
        ("eflags", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("ss", ctypes.c_uint64),
        ("fs_base", ctypes.c_uint64),
        ("gs_base", ctypes.c_uint64),
        ("ds", ctypes.c_uint64),
        ("es", ctypes.c_uint64),
        ("fs", ctypes.c_uint64),
        ("gs", ctypes.c_uint64),
    ]


def run(pov_path, target_path, *, flag=None, result=None):
    if result is None:
        result = {}

    if not flag:
        flag = os.urandom(4096)
    assert len(flag) == 4096
    flag_fd = os.memfd_create('flag')
    flag_path = f'/proc/{os.getpid()}/fd/{flag_fd}'
    os.write(flag_fd, flag)

    result['flag'] = flag.decode('latin')

    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)

    def dup_child_3():
        os.dup2(child_conn.fileno(), 3, inheritable=True)

    pov_seed = str(int.from_bytes(os.urandom(3), 'little'))
    pov_popen = subprocess.Popen(['qemu-cgc/i386-linux-user/qemu-i386', '-seed', pov_seed, pov_path],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL,
                                 pass_fds=(3,),
                                 preexec_fn=dup_child_3)

    pov_type = b''.join(os.read(parent_conn.fileno(), 1) for _ in range(4))
    pov_type = int.from_bytes(pov_type, 'little')
    assert pov_type == 2
    os.write(parent_conn.fileno(), TYPE_2_DATA)

    def trace_me():
        libc.ptrace(PTRACE['TRACEME'], 0, 0, 0)

    target_seed = str(int.from_bytes(os.urandom(3), 'little'))
    target_popen = subprocess.Popen(['qemu-cgc/i386-linux-user/qemu-i386', '-magicpregen', flag_path, '-seed', target_seed, target_path],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    preexec_fn=trace_me)

    result['interaction'] = []

    selected = False

    while True:
        pid, status = os.wait()
        if not os.WIFSTOPPED(status):
            break

        sig = os.WSTOPSIG(status)
        if sig != signal.SIGTRAP:
            result['signal'] = sig
            break

        assert pid == target_popen.pid

        regs = user_regs_struct()
        libc.ptrace(PTRACE['GETREGS'], pid, 0, ctypes.byref(regs))

        syscall = SYSCALL_NAME[regs.orig_rax]
        syscall_start = ctypes.c_long(regs.rax).value == -errno.ENOSYS

        reading = SYSCALL_NAME[regs.orig_rax] == 'read' and regs.rdi == 0
        writing = SYSCALL_NAME[regs.orig_rax] == 'write' and regs.rdi == 1

        try:
            if reading and syscall_start:
                count = regs.rdx
                data = pov_popen.stdout.read1(min(count, io.DEFAULT_BUFFER_SIZE))
                result['interaction'].append(('read', count, data.decode('latin')))
                target_popen.stdin.write(data)
                target_popen.stdin.flush()

            elif writing and not syscall_start:
                count = regs.rdx
                data = target_popen.stdout.read(count)
                result['interaction'].append(('write', count, data.decode('latin')))
                pov_popen.stdin.write(data)
                pov_popen.stdin.flush()

        except BrokenPipeError:
            break

        libc.ptrace(PTRACE['SYSCALL'], pid, 0, 0)

    pov_answer = b''.join(os.read(parent_conn.fileno(), 1) for _ in range(4))
    result['pov_answer'] = pov_answer.decode('latin')
    result['pov_answer_correct'] = pov_answer in flag


def main():
    pov_path = sys.argv[1]
    target_path = sys.argv[2]
    assert os.path.isfile(pov_path)
    assert os.path.isfile(target_path)
    flag = sys.argv[3].encode('latin') if len(sys.argv) > 3 else None
    result = {}
    try:
        run(pov_path, target_path, flag=flag, result=result)
    except Exception as e:
        result['error'] = traceback.format_exc()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
