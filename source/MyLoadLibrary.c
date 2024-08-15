#include <windows.h>
#include "Python-dynload.h"

#include "MemoryModule.h"
#include "MyLoadLibrary.h"

// #define VERBOSE /* enable to print debug output */

/*

Windows API:
============

HMODULE LoadLibraryA(LPCSTR)
HMODULE GetModuleHandleA(LPCSTR)
BOOL FreeLibrary(HMODULE)
FARPROC GetProcAddress(HMODULE, LPCSTR)
BOOL GetModuleHandleExW(DWORD, LPCWSTR, HMODULE *);

MemoryModule API:
=================

HMEMORYMODULE MemoryLoadLibrary(void *)
void MemoryFreeLibrary(HMEMORYMODULE)
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR)

HMEMORYMODULE MemoryLoadLibraryEx(void *,
                                 load_func, getproc_func, free_func, userdata)

(there are also some resource functions which are not used here...)

General API in this file:
=========================

HMODULE MyLoadLibrary(LPCSTR, void *, userdata)
HMODULE MyGetModuleHandle(LPCSTR)
BOOL MyFreeLibrary(HMODULE)
FARPROC MyGetProcAddress(HMODULE, LPCSTR)
BOOL WINAPI MyGetModuleHandleExW(DWORD, LPCWSTR, HMODULE *)

*/

/****************************************************************
 * A linked list of loaded MemoryModules.
 */
typedef struct tagLIST {
	union {
		HCUSTOMMODULE module;
		LPWSTR wname;
	};
	LPSTR name;
	struct tagLIST *next;
	struct tagLIST *prev;
	union {
		DWORD refcount;
		void *userdata;
	};
} LIST;

static LIST *libraries;
static LIST *hookcontexts;

int level;

static int dprintf(char *fmt, ...)
{
#ifdef VERBOSE
	va_list marker;
	int i;

	va_start(marker, fmt);
	for (i = 0; i < level; ++i) {
		putchar(' ');
		putchar(' ');
	}
	return vfprintf(stderr, fmt, marker) + 2*level;
#else
	return 0;
#endif
}

#define PUSH() level++
#define POP()  level--

/****************************************************************
 * Search for a loaded MemoryModule in the linked list, either by name
 * or by module handle.
 */
static LIST *_FindMemoryModule(LPCSTR name, HMODULE module)
{
	LIST *lib = libraries;
	while (lib) {
		if (name && 0 == _stricmp(name, lib->name)) {
			dprintf("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount);
			return lib;
		} else if (module == lib->module) {
			dprintf("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount);
			return lib;
		} else {
			lib = lib->next;
		}
	}
	return NULL;
}

/****************************************************************
 * Insert a MemoryModule into the linked list of loaded modules
 */
static LIST *_AddMemoryModule(LPCSTR name, HCUSTOMMODULE module)
{
	LIST *entry = (LIST *)malloc(sizeof(LIST));
	entry->name = _strdup(name);
	entry->module = module;
	entry->next = libraries;
	entry->prev = NULL;
	entry->refcount = 1;
	libraries = entry;
	dprintf("_AddMemoryModule(%s, %p) -> %p[%d]\n",
		name, module, entry, entry->refcount);
	return entry;
}

/****************************************************************
 * Delete a entry from the linked LIST
 */
static void _DelListEntry(LIST *entry)
{
	if (entry == NULL)
		return;
	if (entry->prev)
		entry->prev->next = entry->next;
	if (entry->next)
		entry->next->prev = entry->prev;
	free(entry->name);
	free(entry);
	entry = NULL;
}

/****************************************************************
 * Helper functions for MemoryLoadLibraryEx
 */
static FARPROC _GetProcAddress(HCUSTOMMODULE module, LPCSTR name, void *userdata)
{
	return MyGetProcAddress(module, name);
}

static void _FreeLibrary(HCUSTOMMODULE module, void *userdata)
{
	MyFreeLibrary(module);
}

/*PyObject *CallFindproc(PyObject *findproc, LPCSTR filename)
{
	PyObject *res = NULL;
	PyObject *args = PyTuple_New(1);
	if (args == NULL)
		return NULL;
	if (-1 == PyTuple_SetItem(args, 0, PyUnicode_FromString(filename)))
		return NULL;
	res = PyObject_CallObject(findproc, args);
	Py_DECREF(args);
	return res;
}*/

static HCUSTOMMODULE _LoadLibrary(LPCSTR filename, void *userdata)
{
	HCUSTOMMODULE result;
	LIST *lib;
	dprintf("_LoadLibrary(%s, %p)\n", filename, userdata);
	PUSH();
	lib = _FindMemoryModule(filename, NULL);
	if (lib) {
		lib->refcount += 1;
		POP();
		dprintf("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
			filename, userdata, lib->name, lib->refcount);
		return lib->module;
	}
	if (result = GetModuleHandleA(filename)) {
		POP();
		dprintf("GetModuleHandleA(%s) -> %p\n\n", filename, result);
		return result;
	}
	if (userdata) {
		dprintf("@userdata\n");
		//PyObject *findproc = (PyObject *)userdata;
		// Since we are using the Py_LIMITED_API with dynamic loading
		// we would have to implement PyObject_CallFunction() ourselves,
		// which would be a paint since there is no PyObject_VaCallFunction.
		//
		// So we implement a special CallFindproc function
		// which encapsulates the dance we have to do.
		//int i;
		//PDWORD pdata = (PDWORD)userdata;
		//dprintf("@userdata data = \n");
		//for (i = 0; i <= sizeof(PyObject); i += sizeof(DWORD)) {
		//	dprintf("    %x\n", *pdata);
		//	pdata ++;
		//}
		char *data;
		size_t size = 0;
		if (PyCallable_Check((PyObject *)userdata)) {
			PyGILState_STATE oldstate = PyGILState_Ensure();
			PyObject *res = PyObject_CallFunction(((PyObject *)userdata), "s", filename);
			//res = CallFindproc(findproc, filename);
			dprintf("@userdata() -> %p\n", res);
			if (PyBytes_AsStringAndSize(res, &data, &size) < 0)
				PyErr_Clear();
			Py_XDECREF(res);
			PyGILState_Release(oldstate);
		}
		if (size) {
			result = MemoryLoadLibraryEx(data, size,
				MemoryDefaultAlloc, MemoryDefaultFree,
				_LoadLibrary, _GetProcAddress, _FreeLibrary,
				userdata);
			if (result) {
				lib = _AddMemoryModule(filename, result);
				POP();
				dprintf("_LoadLibrary(%s, %p) -> %p %s[%d]\n\n",
					filename, userdata, lib->module, lib->name, lib->refcount);
				return lib->module;
			} else {
				dprintf("_LoadLibrary(%s, %p) failed with error %d\n",
					filename, userdata, GetLastError());
			}
		}
	}
	SetLastError(0);
	result = (HCUSTOMMODULE)LoadLibraryA(filename);
	POP();
	dprintf("LoadLibraryA(%s) -> %p\n\n", filename, result);
	return result;
}

/****************************************************************
 * Public functions
 */
HMODULE MyGetModuleHandle(LPCSTR name)
{
	LIST *lib;
	lib = _FindMemoryModule(name, NULL);
	if (lib)
		return lib->module;
	SetLastError(0);
    return NULL;
	//return GetModuleHandle(name);
}

HMODULE MyLoadLibrary(LPCSTR name, void *bytes, size_t size, void *userdata)
{
	if (userdata) {
		HCUSTOMMODULE mod = _LoadLibrary(name, userdata);
		if (mod)
			return mod;
	} else if (bytes) {
		HCUSTOMMODULE mod = MemoryLoadLibraryEx(bytes, size,
							MemoryDefaultAlloc, MemoryDefaultFree,
							_LoadLibrary,
							_GetProcAddress,
							_FreeLibrary,
							userdata);
		if (mod) {
			LIST *lib = _AddMemoryModule(name, mod);
			return lib->module;
		}
	}
	return LoadLibraryA(name);
}

BOOL MyFreeLibrary(HMODULE module)
{
	LIST *lib = _FindMemoryModule(NULL, module);
	if (lib) {
		if (--lib->refcount == 0) {
			MemoryFreeLibrary(module);
			_DelListEntry(lib);
		}
		return TRUE;
	} else {
		SetLastError(0);
		return FreeLibrary(module);
	}
}

BOOL WINAPI MyGetModuleHandleExW(DWORD flags, LPCWSTR modname, HMODULE *pmodule)
{
	if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS && pmodule != NULL) {
		*pmodule = GetModuleHandle(NULL);
		return TRUE;
	}
	return GetModuleHandleExW(flags, modname, pmodule);
}

FARPROC MyGetProcAddress(HMODULE module, LPCSTR procname)
{
	FARPROC proc;
	LIST *lib = _FindMemoryModule(NULL, module);
	if (lib)
		proc = MemoryGetProcAddress(lib->module, procname);
	else {
		SetLastError(0);
		proc = GetProcAddress(module, procname);
		if (proc == (FARPROC)&GetModuleHandleExW)
			proc = (FARPROC)MyGetModuleHandleExW;
	}
	return proc;
}

/****************************************************************
 * Hook functions
 */
extern WORD Py_Minor_Version;

/* Insert a MemoryModule into the linked list of loaded modules */
void SetHookContext(LPCSTR name, PyObject *userdata)
{
	dprintf("SetHookContext(%s, %p)\n", name, userdata);
	PyObject *wname = PyUnicode_FromString(name);
	LIST *entry = (LIST *)malloc(sizeof(LIST));
	entry->wname = _wcsdup(PyUnicode_AsWideCharString(wname, NULL));
	entry->name = _strdup(name);
	entry->next = hookcontexts;
	entry->prev = NULL;
	entry->userdata = (void *)userdata;
	hookcontexts = entry;
	Py_INCREF(userdata);
	Py_DECREF(wname);
	dprintf("SetHookContext(%s, %p) -> NULL\n", name, userdata);
}

static LIST *_FindHookContext(LPCSTR name, LPCWSTR wname)
{
	LIST *context = hookcontexts;
	while (context) {
		if ((name && 0 == strcmp(name, context->name)) ||
			(wname && 0 == wcscmp(wname, context->wname))) {
			dprintf("_FindHookContext(%s, %ls) -> %p %s\n", name, wname, context, context->name);
			return context;
		}
		context = context->next;
	}
	return NULL;
}

HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	dprintf("LoadLibraryExWHook(%ls, %d, %x)\n", lpLibFileName, hFile, dwFlags);
	HMODULE hmodule = NULL;
	LIST *context = _FindHookContext(NULL, lpLibFileName);

	if (context) {
		hmodule = _LoadLibrary(context->name, context->userdata);
		//free(context->wname);
		//Py_DECREF((PyObject *)context->userdata);
		if (hmodule) {
			dprintf("LoadLibraryExWHook(%ls, %d, %x) -> %d\n", lpLibFileName, hFile, dwFlags, hmodule);
			goto finally;
		}
	}

	hmodule = LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	dprintf("LoadLibraryExW(%ls, %d, %x) -> %d\n", lpLibFileName, hFile, dwFlags, hmodule);

finally:
	_DelListEntry(context);
	return hmodule;
}

FARPROC WINAPI GetProcAddressHook(HMODULE hModule, LPCSTR lpProcName)
{
	return MyGetProcAddress(hModule, lpProcName);
}

BOOL WINAPI FreeLibraryHook(HMODULE hLibModule)
{
	return MyFreeLibrary(hLibModule);
}
