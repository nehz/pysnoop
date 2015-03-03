'''
Function hooking class
Created on 09/02/2011

@author: Zhen
'''
import ctypes
import copy
import struct
import pydbg.windows_h as windows
import pydbg.defines as defines
import pydasm
import Pyro.core
from Queue import Queue

kernel32 = ctypes.windll.kernel32

portable_jmp_template  = "\x68\xAA\xAA\xAA\xAA\xC3"
portable_call_template = "\x50\x50\x9C\xE8\x00\x00\x00\x00\x58\x83\xC0\x10\x9D" \
    "\x89\x44\x24\x04\x58\x68\xAA\xAA\xAA\xAA\xC3"

hook_db             = {}
data_limit          = 1000000

hook_stub_template  = None
hook_stub_marker    = 0xABCDEF68
stack_unwind_levels = 20
trace_param_levels  = 2
jmp_size            = 5

class _hook_info(object):
    def __init__(self,
        addr, chain, tag, header_bytes, trampoline, hook_stub, callbacks,
        gather_data, trace_on):

        #read only
        self._address = addr
        self._chain = chain
        self._tag = tag
        self._header_bytes = header_bytes
        self._trampoline = trampoline
        self._hook_stub = hook_stub

        #parameters
        self.stack_unwind_level = stack_unwind_levels
        self.trace_param_levels = trace_param_levels
        self.trace = []
        self.trace_on = trace_on
        self.callbacks = callbacks
        self.gather_data = gather_data

        #output
        self.data = Queue(data_limit)

class _reader(object):
    def __getitem__(self, key):
        key += self.offset
        curr_addr = self.addr + key*4
        start = page_start(self.addr)
        end = page_end(self.addr)

        if end < curr_addr or curr_addr < start:
            raise Exception("Warning: Reading beyond stack")

        return self.sp[key]

    def __setitem__(self, key, value):
        key += self.offset
        curr_addr = self.addr + key*4
        start = page_start(self.addr)
        end = page_end(self.addr)

        if end < curr_addr or curr_addr < start:
            raise Exception("Warning: Reading beyond stack")

        self.sp[key] = value

    def __init__(self, sp, type=ctypes.c_uint):
        self.addr = sp
        self.sp = ctypes.pointer(type.from_address(sp))
        self.offset = 0

class _state(object):
    _capture = [
        'flags',
        'edi', 'esi', 'ebp', 'esp',
        'ebx', 'edx', 'ecx','eax',
        'ret_addr'
    ]

def hook_handler(addr, chain, sp):
    state = _state()
    reader = _reader(sp)

    #read registers + flag
    for i, x in enumerate(state._capture):
        setattr(state, x, reader[i])

    #params
    reader.offset = 10
    hook_info = hook_db[addr][chain]

    if hook_info.gather_data:
        state.param = range(hook_info.stack_unwind_level)
        state.param = map(lambda x: reader[x], state.param)

        #trace params
        if not hook_info.trace:
            trace = xrange(hook_info.stack_unwind_level)
        else:
            trace = hook_info.trace

        state.trace_param = {}
        state.caller = []
        v = lambda x, y: y.from_address(x).value

        for i in trace:
            state.trace_param[i] = []
            param_addr = reader[i]

            if not hook_info.trace_on:
                continue

            for j in xrange(hook_info.trace_param_levels):
                mem_info = virtual_query(param_addr)

                #invalid memory
                if not mem_info or mem_info.State == defines.MEM_FREE:
                    break

                old_protect = \
                    protect(param_addr, 1, defines.PAGE_EXECUTE_READWRITE, True)

                #potential caller addr
                if j == 0:
                    opcode = _reader(param_addr, type=ctypes.c_ubyte)
                    #check JMP/CALL
                    if opcode[-5] in [0xE9, 0xE8]:
                        state.caller += [param_addr - 5]
                    #check RET(N/NF/F)
                    if opcode[-1] in [0xC3, 0xCA]:
                        state.caller += [param_addr - 1]
                    if opcode[-3] in [0xC2, 0xCB]:
                        state.caller += [param_addr - 3]

                #TODO: other record types
                #TODO: size of trace string (non null terminated) e.g packets
                data = (param_addr, ctypes.string_at(param_addr))

                #trace down
                param_addr = v(param_addr, ctypes.c_uint)

                protect(param_addr, 1, old_protect, True)
                state.trace_param[i].append(data)

        #store info
        try:
            hook_info.data.put_nowait(copy.deepcopy(state))
        except:
            pass
    else:
        state.param = []

    #callbacks
    for x in hook_info.callbacks:
        x(state, reader)

    #apply filter
    #TODO
    #write params
    #if hook_info.gather_data:
    #    for i in xrange(hook_info.stack_unwind_level):
    #        reader[i] = state.param[i]

    #write registers + flag
    reader.offset = 0
    for i, x in enumerate(state._capture):
        reader[i] = getattr(state, x)


def make_jmp(addr, dst):
    rel = dst-addr-jmp_size
    return '\xE9' + struct.pack('I', rel & 0xFFFFFFFF)

def create(addr, callback=None, gather=False, trace=False, tag=""):
    if not hook_stub_template:
        raise Exception("Error: Hook engine not yet loaded")

    if type(addr) is not int:
        try:
            addr = int(addr)
        except:
            raise Exception("Error: Hook addr is invalid")

    callbacks = [callback] if callback else []

    _size = len(hook_stub_template) + 100
    if (addr+_size) > page_end(addr):
        raise Exception("Error: placing hook on page boundary")

    #unprotect
    old_protect = protect(addr, _size, defines.PAGE_EXECUTE_READWRITE)

    #copy of header bytes
    header_bytes = ctypes.create_string_buffer(_size)
    ctypes.memmove(header_bytes, addr, ctypes.sizeof(header_bytes))
    header_bytes = header_bytes.raw

    header_size = 0
    prolog = []
    while True:
        i = pydasm.get_instruction(header_bytes[header_size:], pydasm.MODE_32)
        if not i:
            Exception("Error: Decoding asm instruction failed")

        #TODO: code jmp/etc for all cases in header bytes
        #Fix if relative JMPs in header bytes
        #JMP
        if i.opcode == 0xE9 and i.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE:
            absjmp = i.op1.immediate + addr + header_size + jmp_size
            prolog += portable_jmp_template.replace('\xAA\xAA\xAA\xAA',
                struct.pack('I', absjmp))

        #CALL
        elif i.opcode == 0xE8 and i.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE:
            absjmp = i.op1.immediate + addr + header_size + jmp_size
            prolog += portable_call_template.replace('\xAA\xAA\xAA\xAA',
                struct.pack('I', absjmp))

        #JMP SHORT
        elif i.opcode == 0xEB:
            pass

        #JCX
        elif i.opcode == 0xE3:
            pass

        #JCC SHORT
        elif 0x70 < i.opcode < 0x7F:
            pass

        #JCC NEAR
        #elif 0x80 < i.opcode < 0x8F:
        #    pass

        #RET/RETN/RETFN/RETF
        elif i.opcode in [0xC2, 0xC3, 0xCA, 0xCB]:
            raise Exception("Possibily writing hook past function")

        #do not need to worry
        else:
            prolog += header_bytes[header_size:header_size + i.length]

        if len(prolog) == header_size:
            raise Exception("Unable to fix relative JXX/CALLs in header bytes")

        header_size += i.length
        if header_size >= jmp_size:
            break

    prolog = ''.join(prolog)
    header_bytes = header_bytes[:header_size]

    #check if new hook and make new entry
    if addr not in hook_db:
        hook_db[addr] = []

    #chain number
    chain = len(hook_db[addr])

    #create trampoline function
    epilog = portable_jmp_template.replace('\xAA\xAA\xAA\xAA',
        struct.pack('I', addr+header_size))
    trampoline = ctypes.create_string_buffer(prolog + epilog)
    protect(ctypes.addressof(trampoline), len(trampoline),
        defines.PAGE_EXECUTE_READWRITE)

    #create tailored hook_stub
    hook_stub = hook_stub_template
    hook_stub = hook_stub.replace('\xAA\xAA\xAA\xAA', struct.pack('I', addr))
    hook_stub = hook_stub.replace('\xBB\xBB\xBB\xBB', struct.pack('I', chain))
    hook_stub = hook_stub.replace('\xCC\xCC\xCC\xCC',
        struct.pack('I', ctypes.addressof(trampoline)))
    hook_stub = ctypes.create_string_buffer(hook_stub)
    protect(ctypes.addressof(hook_stub), len(hook_stub),
        defines.PAGE_EXECUTE_READWRITE)

    #nop out original header bytes
    ctypes.memmove(addr, '\x90'*header_size, header_size)
    #make jmp
    jmp = make_jmp(addr, ctypes.addressof(hook_stub))
    ctypes.memmove(addr, jmp, len(jmp))

    #store hook info
    data = _hook_info(
        addr, chain, tag,
        header_bytes, trampoline, hook_stub,
        callbacks, gather, trace)

    hook_db[addr] += [data]

    #undo unprotect
    protect(addr, _size, old_protect)

    return data

def remove(addr):
    if not hook_stub_template:
        raise Exception("Error: Hook engine not yet loaded")

    if addr not in hook_db:
        raise Exception("Error: Addr not hooked")

    hook_chain = hook_db[addr][-1]

    size = len(hook_chain._header_bytes)
    old_protect = protect(addr, size, defines.PAGE_EXECUTE_READWRITE)
    ctypes.memmove(addr, hook_chain._header_bytes, size)
    protect(addr, size, old_protect)

    del hook_db[addr][-1]
    ret = len(hook_db[addr])

    #return true if still hook chains exist
    if not hook_db[addr]:
        del hook_db[addr]

    return ret

def remove_all(addr):
    if not hook_stub_template:
        raise Exception("Error: Hook engine not yet loaded")

    if addr not in hook_db:
        raise Exception("Error: Addr not hooked")

    hook_chain = hook_db[addr][0]

    size = len(hook_chain._header_bytes)
    old_protect = protect(addr, size, defines.PAGE_EXECUTE_READWRITE)
    ctypes.memmove(addr, hook_chain._header_bytes, size)
    protect(addr, size, old_protect)

    del hook_db[addr]

def protect(addr, size, protect, ignore=False):
    old_protect = ctypes.c_uint(0)
    if not kernel32.VirtualProtect(addr, size, protect, ctypes.byref(old_protect)):
        if not ignore:
            raise Exception("Could not set memory protection addr:", addr)
        pass

    return old_protect

def virtual_query(addr):
    info = windows.MEMORY_BASIC_INFORMATION()
    if kernel32.VirtualQuery(addr, ctypes.byref(info), ctypes.sizeof(info)):
        return info
    else:
        return None

def page_end(addr):
    info = virtual_query(addr)
    if not info and not info.BaseAddress:
        raise Exception("Invalid address")

    return info.BaseAddress + info.RegionSize - 1

def page_start(addr):
    info = virtual_query(addr)
    if not info and not info.BaseAddress:
        raise Exception("Invalid address")

    return info.BaseAddress

def init(hook_stub_addr):
    global hook_stub_template
    count = page_end(hook_stub_addr) - hook_stub_addr
    buffer = ctypes.create_string_buffer(count)
    ctypes.memmove(buffer, hook_stub_addr, count)

    buffer = buffer.raw
    buffer = buffer.split(struct.pack('I', hook_stub_marker))
    if len(buffer) < 2:
        raise Exception("Failed to init hook, invalid hook_stub in dll")

    hook_stub_template = buffer[0]

class pyro_proxy(Pyro.core.ObjBase):
    def __init__(self):
        Pyro.core.ObjBase.__init__(self)

    def __getattr__(self, name):
        if name not in globals():
            raise AttributeError(name)

        if hasattr(globals()[name], '__call__'):
            return globals()[name]
        else:
            raise AttributeError("No variable access")

    #get hook_db
    def hook_db(self):
        return hook_db