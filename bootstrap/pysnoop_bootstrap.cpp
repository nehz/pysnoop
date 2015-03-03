#include "pysnoop_bootstrap.h"

char loader_path[MAX_STR];
bool loaded = false;
int  undo_on_hook = true;
bool hook_entered = false;

PyObject *module	= NULL;
PyObject *dict		= NULL;
PyObject *func		= NULL;

void python_push(int id, int chain, void *sp) {
	if (!Py_IsInitialized()) {
		MessageBoxA(NULL, "Error: Loader has not started yet", "", 0);
		return;
	}

	PyGILState_STATE gstate;
	gstate = PyGILState_Ensure();

	if (module == NULL) {
		module = PyImport_Import(PyString_FromString("hook"));
		dict = PyModule_GetDict(module);
		func = PyDict_GetItemString(dict, "hook_handler");

		if (!PyCallable_Check(func)) {
			MessageBoxA(NULL, "Error: Cannot find hook_handler", "", 0);
			goto exit;
		}
	}
	PyObject *args = PyTuple_New(3);
	PyTuple_SetItem(args, 0, PyInt_FromLong(id));
	PyTuple_SetItem(args, 1, PyInt_FromLong(chain));
	PyTuple_SetItem(args, 2, PyInt_FromLong((long)sp));
	PyObject_CallObject(func, args);

exit:
	PyGILState_Release(gstate);
	return;
}

NAKED void hook_stub() {
	__asm {
		pushad
		pushfd
	}

	if (!hook_entered) {
		if(undo_on_hook)
			hook_entered = true;

		__asm {
			//push up into python
			push esp
			//chain no
			push 0xBBBBBBBB
			//id=hook addr
			push 0xAAAAAAAA
			//get eip
			call next
next:
			//eip in eax
			pop eax
			//work out return addr
			add eax, 11
			push eax
			push python_push
			retn
			add esp, 4 * 3
		}

		hook_entered = false;
	}

	__asm {
		popfd
		popad

		//call trampoline
		push 0xCCCCCCCC
		retn

		//end of func marker
		push 0x00ABCDEF
	}
}

void loader_thread() {
	if (Py_IsInitialized()) {
		//MessageBoxA(NULL, "Error: An existing python interpreter exists already", "", 0);
		//return;
		PyEval_AcquireLock();
		Py_NewInterpreter();
		PyEval_ReleaseLock();
	}
	char exec[MAX_STR] = "execfile(\"";
	strcat_s(exec, MAX_STR, loader_path);
	strcat_s(exec, MAX_STR, "\")");

	Py_Initialize();
	PyRun_SimpleString(exec);

	MessageBoxA(NULL, "Error: Loader has quit unexpectedly", "", 0);
}

int start_loader(void *_x) {
	if (!strlen(loader_path) || loaded) {
		return 0;
	}
	loaded = true;
	if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)loader_thread, NULL, 0, NULL)) {
		MessageBoxA(NULL, "Error: Could not create loader thread", "", 0);
	}
	return 1;
}

bool APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			start_loader(0);
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
