#ifndef GENERALLOADLIBRARY_H
#define GENERALLOADLIBRARY_H

HMODULE MyLoadLibrary(LPCSTR, void *, size_t, void *);

HMODULE MyGetModuleHandle(LPCSTR);

BOOL MyFreeLibrary(HMODULE);

FARPROC MyGetProcAddress(HMODULE, LPCSTR);

HMODULE WINAPI LoadLibraryExWHook(LPCWSTR, HANDLE, DWORD);

FARPROC WINAPI GetProcAddressHook(HMODULE, LPCSTR);

BOOL WINAPI FreeLibraryHook(HMODULE);

void SetHookContext(LPCSTR, void *);

#endif
