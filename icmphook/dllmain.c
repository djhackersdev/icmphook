#include <windows.h>

#include "icmphook/hook.h"

BOOL WINAPI DllMain(HMODULE mod, DWORD cause, void *ctx)
{
    HRESULT hr;

    if (cause != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    hr = hook_init();

    return SUCCEEDED(hr);
}
