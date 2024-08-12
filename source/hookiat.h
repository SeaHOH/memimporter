#ifndef HOOKIAT_H
#define HOOKIAT_H

#define DWORD_AT(mem) (*(DWORD *)(mem))
#define WORD_AT(mem)  (*(WORD *)(mem))

typedef struct {
    FARPROC *FunctionAddress;
    FARPROC OriginalFunction;
    FARPROC FunctionHook;
} IATHookInfo;

IATHookInfo *HookImportAddressTable(LPCWSTR, HMODULE, LPCSTR, LPCSTR, void *);
void UnHookImportAddressTable(IATHookInfo *);
BOOL IsHooked(IATHookInfo *);

#endif  // HOOKIAT_H
