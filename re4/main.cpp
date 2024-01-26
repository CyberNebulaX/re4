#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <tchar.h>
#include <vector>

DWORD_PTR GetModuleBaseAddress(DWORD procId, LPCTSTR modName) {
    DWORD_PTR modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (_tcsicmp(modEntry.szModule, modName) == 0) {
                    modBaseAddr = (DWORD_PTR)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
    }
    return modBaseAddr;
}

DWORD FindProcessId(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32; // Use the wide-character version
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe32)) { // Use the wide-character function
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe32)); // Use the wide-character function
        }
        CloseHandle(hSnap);
    }
    return processId;
}

int PointerChainResolution(HANDLE hProcess, DWORD_PTR baseModuleAddress,  std::vector<unsigned int> offsets) {
    DWORD_PTR addr = baseModuleAddress;
    for (unsigned int i = 0; i < offsets.size(); i++)
    {
        ReadProcessMemory(hProcess, (LPCVOID)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}

int main() {
    const wchar_t* processName = L"re4.exe"; // Replace with the actual process name
    DWORD procId = FindProcessId(processName); // Implement this function as shown before

    if (procId == 0) {
        std::wcout << L"Process not found.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, procId);
    if (hProcess == NULL) {
        std::wcout << L"Failed to open process for reading.\n";
        return 1;
    }

    DWORD_PTR baseAddress = GetModuleBaseAddress(procId, processName); // Implement this function as shown before
    DWORD_PTR pointerAddress = baseAddress + 0x0DBB5C80; // Base offset from Cheat Engine
    std::vector<unsigned int> offsets = { 0x30, 0x60, 0x84 };
    DWORD_PTR ammoAddress = PointerChainResolution(hProcess, pointerAddress, offsets);
    int ammoValue = 0;

    ReadProcessMemory(hProcess, LPCVOID(ammoAddress), &ammoValue, sizeof(ammoValue), 0);

    std::wcout << L"Ammo value: " << ammoValue << std::endl;

    CloseHandle(hProcess);
    return 0;
}