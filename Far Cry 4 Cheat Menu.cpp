#include <Windows.h>
#include <iostream>

// Function to enable fly mode
void enableFlyMode() {
    // AOB scan for fly mode
    BYTE flyBytes[] = { 0x0F, 0x28, 0x20, 0x48, 0x8B, 0xC3, 0x0F, 0x28, 0xC4 };
    DWORD flyAddress = FindPattern("FC64.dll", flyBytes, sizeof(flyBytes));
    if (flyAddress != 0) {
        // Allocate memory for the fly mode script
        BYTE* newmem = (BYTE*)VirtualAllocEx(GetCurrentProcess(), NULL, 2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (newmem != NULL) {
            // Write the fly mode script to the allocated memory
            DWORD oldProtect;
            VirtualProtectEx(GetCurrentProcess(), newmem, 2048, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(DWORD*)(newmem + 0x00) = 0x488B442408; // mov rax, [rsp+8]
            *(DWORD*)(newmem + 0x05) = 0x0F284420; // movaps xmm4, [rax]
            *(DWORD*)(newmem + 0x0A) = 0x488B442408; // mov rax, [rsp+8]
            *(DWORD*)(newmem + 0x0F) = 0xC6450880F6; // mov byte ptr [rax+8], 0F6
            *(DWORD*)(newmem + 0x14) = 0x488B442408; // mov rax, [rsp+8]
            *(DWORD*)(newmem + 0x19) = 0xC6450881F6; // mov byte ptr [rax+8], 1F6
            VirtualProtectEx(GetCurrentProcess(), newmem, 2048, oldProtect, &oldProtect);

            // Jump to the fly mode script
            DWORD jmpAddress = flyAddress + 0x45A2D5;
            *(DWORD*)jmpAddress = 0xE9;
            *(DWORD*)(jmpAddress + 1) = (DWORD)newmem - jmpAddress - 5;
        }
    }
}

// Function to bypass jump and fall
void bypassJumpAndFall() {
    // AOB scan for jump and fall
    BYTE jumpFallBytes[] = { 0xC6, 0x45, 0x88, 0x00, 0xF6, 0x80, 0xE8, 0x01, 0x00, 0x00, 0x80 };
    DWORD jumpFallAddress = FindPattern("FC64.dll", jumpFallBytes, sizeof(jumpFallBytes));
    if (jumpFallAddress != 0) {
        // Write the bypass script to the jump and fall address
        DWORD oldProtect;
        VirtualProtectEx(GetCurrentProcess(), (LPVOID)jumpFallAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
        *(BYTE*)jumpFallAddress = 0xC6; // mov byte ptr [rax+8], 1
        VirtualProtectEx(GetCurrentProcess(), (LPVOID)jumpFallAddress, 1, oldProtect, &oldProtect);
    }
}

int main() {
    // Enable fly mode
    enableFlyMode();

    // Bypass jump and fall
    bypassJumpAndFall();

    return 0;
}