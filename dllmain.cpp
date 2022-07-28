#include "util.hpp"

bool __stdcall entry(HINSTANCE dll, unsigned short call_reason, void*)
{
    if (call_reason == 1) {

        MODULEINFO module_info = { 0 };

        K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("engine.dll"), &module_info, sizeof(MODULEINFO));
        
        const uintptr_t start_address = uintptr_t(module_info.lpBaseOfDll);
        const uintptr_t patch_addr = sigscan(start_address, start_address + module_info.SizeOfImage, "7C ? 8B 06 8B CE FF 50 18 50 68 ? ? ? ? FF 15 ? ? ? ? 83 C4 ? B0 ?");
        
        // patch jl to jmp
        patch(reinterpret_cast<void*>(patch_addr), reinterpret_cast<unsigned char*>("\xEB\x21"), 2);
    }
    return call_reason;
}
