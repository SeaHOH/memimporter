#include <windows.h>
#include "hookiat.h"
#ifdef VERBOSE
#include <stdio.h>
#endif


/* PYTHON_SOURCE/Python/dynload_win.c GetPythonImport */

#ifdef _WIN64
/* PE32+ */
#define OPT_MAGIC 0x20B
#define NUM_DICT_OFF 108
#define IMPORT_OFF 120
#define THUNK_WALK 2
#else
/* PE32 */
#define OPT_MAGIC 0x10B
#define NUM_DICT_OFF 92
#define IMPORT_OFF 104
#define THUNK_WALK 1
#endif

IATHookInfo *
HookImportAddressTable(LPCWSTR lpModuleName, HMODULE hModule,
                       LPCSTR module_name, LPCSTR func_name, void *func_hook)
{
    unsigned char *dllbase, *import_data;
    DWORD pe_offset, opt_offset;
    PDWORD pIAT, pINT;
    IATHookInfo *hookinfo = (IATHookInfo *)malloc(sizeof(IATHookInfo));
    hookinfo->FunctionAddress = 0;
    hookinfo->OriginalFunction = 0;
    hookinfo->FunctionHook = (FARPROC)func_hook;

    /* Safety check input */
    if (hModule == NULL){
        hModule = GetModuleHandleW(lpModuleName);
        if (hModule == NULL) {
            goto finally;
        }
    }

    /* Module instance is also the base load address.  First portion of
       memory is the MS-DOS loader, which holds the offset to the PE
       header (from the load base) at 0x3C */
    dllbase = (unsigned char *)hModule;
    pe_offset = DWORD_AT(dllbase + 0x3C);

    /* The PE signature must be "PE\0\0" */
    if (memcmp(dllbase+pe_offset,"PE\0\0",4)) {
        goto finally;
    }

    /* Following the PE signature is the standard COFF header (20
       bytes) and then the optional header.  The optional header starts
       with a magic value of 0x10B for PE32 or 0x20B for PE32+ (PE32+
       uses 64-bits for some fields).  It might also be 0x107 for a ROM
       image, but we don't process that here.

       The optional header ends with a data dictionary that directly
       points to certain types of data, among them the import entries
       (in the second table entry). Based on the header type, we
       determine offsets for the data dictionary count and the entry
       within the dictionary pointing to the imports. */

    opt_offset = pe_offset + 4 + 20;
    if (OPT_MAGIC != WORD_AT(dllbase + opt_offset)) {
        /* Unsupported */
        goto finally;
    }

    /* Now if an import table exists, walk the list of imports. */

    if (DWORD_AT(dllbase + opt_offset + NUM_DICT_OFF) >= 2) {
        /* We have at least 2 tables - the import table is the second
           one.  But still it may be that the table size is zero */
        if (0 == DWORD_AT(dllbase + opt_offset + IMPORT_OFF + sizeof(DWORD)))
            goto finally;
        import_data = dllbase + DWORD_AT(dllbase + opt_offset + IMPORT_OFF);
        while (DWORD_AT(import_data)) {
            if (_stricmp(dllbase + DWORD_AT(import_data+12), module_name) == 0) {
#ifdef VERBOSE
                printf("found %s\n", module_name);
#endif
                /* Found the import module */
                pINT = (PDWORD)(dllbase + DWORD_AT(import_data));
                pIAT = (PDWORD)(dllbase + DWORD_AT(import_data+16));
                while (*pINT) {
                    if (!IMAGE_SNAP_BY_ORDINAL(*pINT)) {
#ifdef VERBOSE
                            printf("walk %s\n", dllbase + *pINT + 2);
#endif
                        if (_stricmp(dllbase + *pINT + 2, func_name) == 0) {
#ifdef VERBOSE
                            printf("found %s\n", func_name);
#endif
                            /* Found the import function then hook it */
                            hookinfo->FunctionAddress = (FARPROC *)pIAT;
                            hookinfo->OriginalFunction = *(FARPROC *)pIAT;
                            *(FARPROC *)pIAT = hookinfo->FunctionHook;
                            goto finally;
                        }
                    }
                    pINT += THUNK_WALK;
                    pIAT += THUNK_WALK;
                }
            }
            import_data += 20;
        }
    }

finally:
    return hookinfo;
}

void
UnHookImportAddressTable(IATHookInfo *hookinfo)
{
    if (IsHooked(hookinfo)) {
        *hookinfo->FunctionAddress = hookinfo->OriginalFunction;
    }
}

BOOL
IsHooked(IATHookInfo *hookinfo)
{
    if (hookinfo &&
            hookinfo->FunctionAddress &&
           *hookinfo->FunctionAddress != hookinfo->OriginalFunction) {
        return TRUE;
    }
    return FALSE;
}
