/* Generated by tools/xxx.py */

#ifndef PYTHON_DYNLOAD_NPVAR_H
#define PYTHON_DYNLOAD_NPVAR_H

#ifdef  DATA_PTR

/* Define non-pointer variables via macros */
#define Py_OptimizeFlag (*Py_OptimizeFlag_Ptr)

/* Define non-pointer variables' help variables via macros */
DATA_PTR(int, Py_OptimizeFlag);

#endif

#endif  // PYTHON_DYNLOAD_NPVAR_H
