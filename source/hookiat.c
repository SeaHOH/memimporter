#include <windows.h>
#include "hookiat.h"
#ifdef VERBOSE
#include <stdio.h>
#endif


/* PYTHON_SOURCE/Python/dynload_win.c GetPythonImport */

IATHookInfo *
HookImportAddressTable(LPCWSTR lpModuleName, HMODULE hModule,
                       LPCSTR module_name, LPCSTR func_name, void *func_hook)
{
    unsigned char *dllbase, *import_data;
    DWORD pe_offset, opt_offset;
    WORD opt_magic;
    int num_dict_off, import_off;
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
    opt_magic = WORD_AT(dllbase + opt_offset);
    if (opt_magic == 0x10B) {
        /* PE32 */
        num_dict_off = 92;
        import_off   = 104;
    } else if (opt_magic == 0x20B) {
        /* PE32+ */
        num_dict_off = 108;
        import_off   = 120;
    } else {
        /* Unsupported */
        goto finally;
    }

    /* Now if an import table exists, walk the list of imports. */

    if (DWORD_AT(dllbase + opt_offset + num_dict_off) >= 2) {
        /* We have at least 2 tables - the import table is the second
           one.  But still it may be that the table size is zero */
        if (0 == DWORD_AT(dllbase + opt_offset + import_off + sizeof(DWORD)))
            goto finally;
        import_data = dllbase + DWORD_AT(dllbase + opt_offset + import_off);
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
                    pINT += 4;
                    pIAT += 4;
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
