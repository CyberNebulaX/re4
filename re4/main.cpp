#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <tchar.h>
#include <thread>
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
        PROCESSENTRY32W pe32; 
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe32)) {
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

DWORD_PTR PointerChainResolution(HANDLE hProcess, DWORD_PTR baseModuleAddress,  std::vector<unsigned int> offsets) {
    DWORD_PTR addr = baseModuleAddress;
    for (unsigned int i = 0; i < offsets.size(); i++)
    {
        ReadProcessMemory(hProcess, (LPCVOID)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}

bool updateAmmoInPlace(HANDLE hProcess, DWORD_PTR addressToWriteTo, unsigned int valueToWrite) {

    bool success = FALSE;
    success = WriteProcessMemory(hProcess, LPVOID(addressToWriteTo), &valueToWrite, sizeof(valueToWrite), 0);
    return success;
}

int main() {
    const wchar_t* processName = L"re4.exe"; 
    DWORD procId = FindProcessId(processName);

    if (procId == 0) {
        std::wcout << L"Process not found.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    if (hProcess == NULL) {
        std::wcout << L"Failed to open process for reading.\n";
        return 1;
    }

    DWORD_PTR baseAddress = GetModuleBaseAddress(procId, processName);
    DWORD_PTR pointerAddress = baseAddress + 0x0DBB5C80; // Base offset from Cheat Engine
    std::vector<unsigned int> offsets = { 0x30, 0x60, 0x84 };
    DWORD_PTR ammoAddress = PointerChainResolution(hProcess, pointerAddress, offsets);
    int ammoValue = 0;

    std::wcout << L"Updating ammo value to 10 " << std::endl;

    while (true) {
        // Check if the process is still running
        DWORD exitCode;
        if (!GetExitCodeProcess(hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
            std::wcout << L"Process has exited." << std::endl;
            break;
        }

        // Read the current ammo value
        ReadProcessMemory(hProcess, LPCVOID(ammoAddress), &ammoValue, sizeof(ammoValue), nullptr);

        // If ammo is below 10, refill it. The mag can not hold more than 10 bullets
        if (ammoValue < 10) {
            updateAmmoInPlace(hProcess, ammoAddress, 10);
        }

        // Sleep for a short duration to avoid hammering CPU and game memory
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // remember to close the handle somewhere

    CloseHandle(hProcess);
    return 0;
}