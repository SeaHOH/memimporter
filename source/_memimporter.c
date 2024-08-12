// Need to define these to be able to use SetDllDirectory/GetDllDirectory.
//#define _WIN32_WINNT 0x0502
//#define NTDDI_VERSION 0x05020000

#include <windows.h>
#include "Python-dynload.h"

#include "hookiat.h"
#include "MyLoadLibrary.h"

static char module_doc[] =
"Importer which can load extension modules from memory";

static char set_context_doc[] =
"set_context(pathname, finder) -> None\n"
"\n"
"Before import (LoadLibrary/LoadLibraryEx) a memory module, a context\n"
"is needed for find and get modules' data. It includes the main module's\n"
"path/name and the data finder for later use, works like this:\n"
"\n"
"    main_module_data = finder(pathname)\n"
"    dependency_module_data = finder(dependency_name)";


#if (PY_VERSION_HEX < 0x03040000)
#   error "Python 3.0 - 3.3 are not supported"
#endif


IATHookInfo *hookinfo_LoadLibraryExW = NULL,
            *hookinfo_GetProcAddress = NULL,
            *hookinfo_FreeLibrary = NULL;

static PyObject *
set_context(PyObject *self, PyObject *args)
{
    char *pathname;
    PyObject *findproc;
    if (!PyArg_ParseTuple(args, "sO:set_context", &pathname, &findproc))
        return NULL;
    if (!PyCallable_Check(findproc)) {
        PyErr_SetString(PyExc_TypeError, "second argument must be callable");
        return NULL;
    }
    SetHookContext(pathname, (void *)findproc);
    return NULL;
}

static PyMethodDef methods[] = {
    { "set_context", (PyCFunction)set_context, METH_VARARGS, set_context_doc},
    { NULL, NULL },    /* Sentinel */
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_memimporter", /* m_name */
    module_doc,     /* m_doc */
    -1,             /* m_size */
    methods,        /* m_methods */
    NULL,           /* m_reload */
    NULL,           /* m_traverse */
    NULL,           /* m_clear */
    NULL,           /* m_free */
};

PyMODINIT_FUNC
PyInit__memimporter(void)
{
    LoadPyCore();
    if (hookinfo_LoadLibraryExW == NULL) {
        hookinfo_LoadLibraryExW = HookImportAddressTable(
                    PyCore, hPyCore,
                    "kernel32.dll", "LoadLibraryExW", LoadLibraryExWHook);
    }
    if (IsHooked(hookinfo_LoadLibraryExW)) {
        if (hookinfo_GetProcAddress == NULL) {
            hookinfo_GetProcAddress = HookImportAddressTable(
                    PyCore, hPyCore,
                    "kernel32.dll", "GetProcAddress", GetProcAddressHook);
        }
        if (hookinfo_FreeLibrary == NULL) {
            hookinfo_FreeLibrary = HookImportAddressTable(
                    PyCore, hPyCore,
                    "kernel32.dll", "FreeLibrary", FreeLibraryHook);
        }
        if (!IsHooked(hookinfo_GetProcAddress) ||
            !IsHooked(hookinfo_FreeLibrary) ) {
            UnHookImportAddressTable(hookinfo_LoadLibraryExW);
            UnHookImportAddressTable(hookinfo_GetProcAddress);
            UnHookImportAddressTable(hookinfo_FreeLibrary);
        }
    }
#if defined(DYNLOAD_CORE) || !defined(STANDALONE)
    InitExports();
#endif
    return PyModule_Create(&moduledef);
}
