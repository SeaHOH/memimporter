#ifndef Py_LIMITED_API
#define Py_LIMITED_API 0x03060000
#endif

#if defined(DYNLOAD_CORE) && defined(STANDALONE)
#   ifdef Py_ENABLE_SHARED
#   undef Py_ENABLE_SHARED
#   endif
#   ifndef PYTHON_DYNLOAD_H
#   define PYTHON_DYNLOAD_H
        /* See "PYTHON_SOURCE/Include/pyport.h" */
        /* We import functions ourselves */
#       define PyAPI_FUNC(RTYPE) extern RTYPE
        /* We import pointer variables ourselves */
#       ifdef PYTHON_DYNLOAD_C
            /* We need define pointer variables in Python headers */
#           define PyAPI_DATA(RTYPE) RTYPE
#       else
#           define PyAPI_DATA(RTYPE) extern RTYPE
#       endif
#   endif  // PYTHON_DYNLOAD_H
#endif

#include <Python.h>

#if defined(DYNLOAD_CORE) || !defined(STANDALONE)

#   ifdef PYTHON_DYNLOAD_C

    /* Function definitions */
#   include "Python-dynload-func.h"

    /* Define non-pointer variables' help macros */
#   define DATA_PTR(type, name) type *name##_Ptr

#   else  // PYTHON_DYNLOAD_C

#   define DATA_PTR(type, name) extern type *name##_Ptr

#   endif  // PYTHON_DYNLOAD_C

    /* Non-pointer variables definitions */
#   include "Python-dynload-npvar.h"

#endif  // DYNLOAD_CORE

#ifndef PYTHON_DYNLOAD_C

extern wchar_t PyCore[];
extern HMODULE hPyCore;
extern DWORD Py_Version_Hex;
extern WORD Py_Minor_Version;
extern void LoadPyCore(void);
extern void InitExports(void);

#endif  // PYTHON_DYNLOAD_C
