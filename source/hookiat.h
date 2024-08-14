#ifndef HOOKIAT_H
#define HOOKIAT_H

typedef struct {
    FARPROC *FunctionAddress;
    FARPROC OriginalFunction;
    FARPROC FunctionHook;
} IATHookInfo;

IATHookInfo *HookImportAddressTable(LPCWSTR, HMODULE, LPCSTR, LPCSTR, void *);
void UnHookImportAddressTable(IATHookInfo *);
BOOL IsHooked(IATHookInfo *);

#endif  // HOOKIAT_H
