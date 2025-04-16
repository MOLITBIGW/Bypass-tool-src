#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <psapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

extern std::vector<std::string> strings;

std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string>& patterns);
bool nullify_string(HANDLE hProcess, void* address, size_t length);

DWORD GetJavawPid() {
    DWORD pid = 0;
    DWORD processIds[1024], cbNeeded, numProcesses;
    if (EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        numProcesses = cbNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < numProcesses; i++) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
            if (hProcess) {
                char processName[MAX_PATH] = { 0 };
                if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName) / sizeof(char))) {
                    if (strcmp(processName, "javaw.exe") == 0) {
                        pid = processIds[i];
                        CloseHandle(hProcess);
                        break;
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    return pid;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << R"(
 ______                                     _______               __ 
|   __ \.--.--.-----.---.-.-----.-----.    |_     _|.-----.-----.|  |
|   __ <|  |  |  _  |  _  |__ --|__ --|      |   |  |  _  |  _  ||  |
|______/|___  |   __|___._|_____|_____|      |___|  |_____|_____||__|
        |_____|__|                                                   

)" << std::endl;

    DWORD pid = GetJavawPid();
    if (pid == 0) {
        std::cout << "javaw.exe not found!\n";
        return 1;
    }

    std::cout << "Minecraft PID: " << pid << "\n";

    auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

    if (!handle) {
        std::cout << "\n Invalid Process.\n";
        return 1;
    }
    else {
        std::cout << "Scanning...\n";

        auto results = pattern_scan(handle, strings);

        std::cout << "Found " << std::dec << results.size() << " Strings. \n";
    }

    std::cout << "\n\n==========================\n";
    std::cout << "   Operation Completed!   \n";
    std::cout << "==========================\n\n";

    MessageBoxW(NULL, L"Operation Completed!", L"blabla", MB_OK);

    return 0;
}

std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string>& patterns) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    std::vector<void*> results;
    MEMORY_BASIC_INFORMATION memInfo;
    uint8_t* address = static_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);

    while (address < sys_info.lpMaximumApplicationAddress && VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            memInfo.Type == MEM_PRIVATE) {

            std::vector<uint8_t> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                std::string_view view(reinterpret_cast<char*>(buffer.data()), bytesRead);

                for (const auto& pattern : patterns) {
                    size_t pos = 0;
                    while ((pos = view.find(pattern, pos)) != std::string_view::npos) {
                        void* found = static_cast<uint8_t*>(memInfo.BaseAddress) + pos;
                        std::cout << "[*] Found string " << pattern << " at " << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(found) << "\n";
                        results.push_back(found);

                        if (nullify_string(hProcess, found, pattern.size())) {
                            std::cout << "[*] Nullified " << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(found) << "\n";
                        }
                        ++pos;
                    }
                }
            }
        }
        address = static_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }
    return results;
}

bool nullify_string(HANDLE hProcess, void* address, size_t length) {
    std::vector<uint8_t> nullData(length, 0x00);
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, address, nullData.data(), nullData.size(), &bytesWritten)) {
        return bytesWritten == nullData.size();
    }
    return false;
}
