/*
  This module allows us to import Python API from dynamically loaded DLL.

  We'll define PyAPI_FUNC and PyAPI_DATA before "#include <Python.h>"，
  if DYNLOAD_CORE has be defined, then anyhow dynamically load can works
  with STANDALONE mode, and don't care whether python3.dll exists.

  Usage:
    `#include <Python.h>` in other files need be replaced with
    `#include "Python-dynload.h"`.

  Problems:
  //- We cannot use vararg functions that have no va_list counterpart.
  //- What about the flags or other data exported from Python?
  //- Error handling MUST be improved...
  //- Should we use a python script to generate this code
  //  from function prototypes automatically?
*/

#include <windows.h>

#define PYTHON_DYNLOAD_C
#include "Python-dynload.h"
#undef PYTHON_DYNLOAD_C

/*
  We have to #define Py_BUILD_CORE when we compile our stuff,
  then the exe doesn't try to link with pythonXY.lib, and also
  the following definitions compile.

  We use MyGetProcAddress to get the functions from the dynamically
  loaded python DLL, so it will work both with the DLL loaded from the
  file system as well as loaded from memory.
*/
#if defined(Py_BUILD_CORE) || defined(DYNLOAD_CORE)
#include "MyLoadLibrary.h"
#define GetProcAddress MyGetProcAddress
#define IMPORT_FUNC(name) (FARPROC)name = GetProcAddress(hPyCore, #name)
#define IMPORT_DATA(name) (FARPROC)name##_Ptr = GetProcAddress(hPyCore, #name)
#define IMPORT_DATA_PTR(name) (void *)name = *((void **)GetProcAddress(hPyCore, #name))
#endif

#ifdef _DEBUG
#define DEBUG_SUFFIX L"_d"
#else
#define DEBUG_SUFFIX L""
#endif


wchar_t PyCore[20];
HMODULE hPyCore;
DWORD Py_Version_Hex = 0;
WORD Py_Minor_Version = 0;

static inline void
_LoadPyCore(WORD py_minor_version)
{
    swprintf(PyCore, sizeof(PyCore), L"python3%d" DEBUG_SUFFIX L".dll", py_minor_version);
    hPyCore = GetModuleHandleW(PyCore);
}

static void
LoadPyVersion(HMODULE hPyDll)
{
    if (hPyDll == NULL)
        return;

    FARPROC address = GetProcAddress(hPyDll, "Py_Version");
    if (address == NULL) {
        /* version <= 3.10 */
        address = GetProcAddress(hPyDll, "Py_GetVersion");
        if (address != NULL) {
            typedef char *(*Py_GetVersionFunction)(void);
            char *strversion = ((Py_GetVersionFunction)address)();
            WORD version = 0;
            while (*strversion != ' ') {
                if (*strversion >= '0' && *strversion <= '9') {
                    version = version * 10 + (WORD)(*strversion - '0');
                } else {
                    Py_Version_Hex <<= 8;
                    Py_Version_Hex |= version << 8;
                    version = 0;
                    if (*strversion != '.') {
                        Py_Version_Hex |= ((WORD)(*strversion - 'a') + 10) << 4;
                        Py_Version_Hex |= (WORD)(strversion[1] - '0');
                        break;
                    }
                }
                strversion++;
            }
            if (*strversion == ' ') {
                Py_Version_Hex <<= 8;
                Py_Version_Hex |= 0xF0;
            }
        }
    } else {
        /* version >= 3.11 */
        Py_Version_Hex = *(DWORD*)address;
    }
    Py_Minor_Version = Py_Version_Hex >> 16 & 0xFF;
}

void
LoadPyCore(void)
{
    WORD py_minor_version;

    if (hPyCore) {
        return;
    }

    LoadPyVersion(GetModuleHandleW(L"python3" DEBUG_SUFFIX L".dll"));
    if (Py_Minor_Version) {
        _LoadPyCore(Py_Minor_Version);
        goto done;
    }

    for (py_minor_version=3; py_minor_version<=14; py_minor_version++) {
        _LoadPyCore(py_minor_version);
        if (hPyCore) {
            LoadPyVersion(hPyCore);
            goto done;
        }
    }
    return;
done:
    SetLastError(0);
}

void
InitExports(void)
{
    static BOOL initialized = FALSE;

    if (initialized) {
        return;
    }
    initialized = TRUE;

    if (!hPyCore)
        LoadPyCore();

#if defined(DYNLOAD_CORE) || defined(Py_BUILD_CORE)

    /* Non-pointer variables START */
    IMPORT_DATA(Py_OptimizeFlag);
    /* Non-pointer variables END */

    /* Pointer variables START */
    IMPORT_DATA_PTR(PyExc_TypeError);
    /* Pointer variables END */

    /* Functions START */
    IMPORT_FUNC(PyArg_ParseTuple);
    IMPORT_FUNC(PyBytes_AsStringAndSize);
    IMPORT_FUNC(PyCallable_Check);
    IMPORT_FUNC(PyErr_Clear);
    IMPORT_FUNC(PyErr_SetString);
    IMPORT_FUNC(PyModule_Create2);
    IMPORT_FUNC(PyObject_CallFunction);
    IMPORT_FUNC(PyUnicode_AsWideCharString);
    IMPORT_FUNC(PyUnicode_FromString);
    /* Functions END */

#endif
}

#ifdef GetProcAddress
#undef GetProcAddress
#endif
