'''
Remote system loader
Created on 08/02/2011

@author: Zhen
'''
import os
import sys
import time
import ctypes
import thread
import code

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

#disable DEP
kernel32.SetProcessDEPPolicy(0)

if kernel32.AllocConsole():
    ENABLE_ECHO_INPUT   = 0x0004
    ENABLE_INSERT_MODE  = 0x0020
    STD_INPUT_HANDLE    = 0xFFFFFFF6

    kernel32.SetConsoleCtrlHandler(None, True)
    kernel32.SetConsoleMode(kernel32.GetStdHandle(STD_INPUT_HANDLE),
        ENABLE_ECHO_INPUT | ENABLE_INSERT_MODE)

    kernel32.SetConsoleTitleA("pysnoop console")
    sys.stdout = open('CONOUT$', 'wt', buffering=0)
    sys.stdin  = open('CONIN$',  'rt', buffering=0)
    sys.stderr = open('CONOUT$', 'wt', buffering=0)
    user32.RemoveMenu(user32.GetSystemMenu(kernel32.GetConsoleWindow(), False), 0xF060, 1)
    user32.DrawMenuBar(kernel32.GetConsoleWindow())

print "pysnoop loading...\n"

#add paths
bootstrap = ctypes.windll.LoadLibrary("bootstrap")
path = os.path.dirname(ctypes.string_at(bootstrap.loader_path))
sys.path.append(path)
print "pysnoop base dir found at:", path.upper()

#init hooking engine
import hook
hook.init(ctypes.c_uint.from_address(ctypes.addressof(bootstrap.hook_stub)).value)
print "hook engine started..."

#start pyro
pyro_path = path + r"\pyro.zip"
sys.path.insert(0, pyro_path)

try:
    import Pyro.core #@UnresolvedImport
    daemon = Pyro.core.Daemon()
    daemon.connect(hook.pyro_proxy(), "hook")

    def pyro_init():
        Pyro.core.initServer()
        daemon.requestLoop()

    print "pyro started on port:", daemon.port
    thread.start_new_thread(pyro_init, ())
except:
    print "unable to start/find pyro!"

print "load complete...\n\n"

addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA("user32"), "MessageBoxA")
#addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA("Ws2_32"), "recv")

info = hook.create(addr, gather=True, trace=True)
hook.create(addr)
user32.MessageBoxA(None, "test0", "test0", 0)

#loader interactive console
print "\ninput console:\n"
def prompt_raw_input(x):
    print ">>>",
    return raw_input(x)

command = code.InteractiveConsole(locals=globals())
more = False
while True:
    if not more:
        print ">>>",
    else:
        print "...",

    try:
        line = command.raw_input()
        more = command.push(line)
    except EOFError:
        while True:
            try:
                command.raw_input()
                break
            except:
                pass
        more = False
    except Exception, e:
        print e

print 'Warning: Console ended unexpectedly'
time.sleep(-1)
