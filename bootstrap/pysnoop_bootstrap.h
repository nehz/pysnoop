#pragma once

#define WIN32_LEAN_AND_MEAN
#define DLL_EXPORT __declspec(dllexport)
#define NAKED __declspec(naked)

#include <windows.h>
#include <stdio.h>
#include <Python.h>

#define MAX_STR FILENAME_MAX*2

extern "C" DLL_EXPORT char loader_path[];
extern "C" DLL_EXPORT int start_loader(void *);
extern "C" DLL_EXPORT void hook_stub();
extern "C" DLL_EXPORT int undo_on_hook;
