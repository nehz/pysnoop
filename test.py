'''
Created on 08/02/2011

@author: Zhen
'''

import sys
print sys.path
import os
print os.path

import os
import time
import thread
import injection
import ctypes
from pydbg import pydbg



dbg = pydbg(False)
inject = injection.inject()

#thread.start_new_thread(dbg.load, (r"c:\windows\system32\calc.exe", None, True))
thread.start_new_thread(dbg.load, (r"c:\python27\python.exe", None, True))
while not dbg.pid:
    time.sleep(0.01)

#dbg.pid = 0x11ac
#dbg.open_process(dbg.pid)

print dbg.pid, os.getcwd() + r"\bootstrap.dll"
base = inject.inject_dll(os.getcwd() + r"\bootstrap.dll", dbg.pid)
print "Injected"

#alternatively use base-local=delta
loader_path = dbg.func_resolve_debuggee("bootstrap.dll", "loader_path")
start_loader = dbg.func_resolve_debuggee("bootstrap.dll", "start_loader")

print start_loader
dbg.write(loader_path, ctypes.create_string_buffer(os.getcwd() + r"\loader.py"))
dbg.call_func(start_loader, dbg.pid)


