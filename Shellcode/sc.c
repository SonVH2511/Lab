#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include <Tlhelp32.h>

#define _CRT_SECURE_NO_WARNINGS

typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);

__declspec(noinline) bool del();
__declspec(noinline) void RestartComputer();

unsigned __int8 shellcode[] = "\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x48\x83\xEC\x38\xC7\x44\x24\x08\x34\x33\x32\x31\xC7\x44\x24\x0C\x72\x65\x77\x71\xC7\x44\x24\x10\x66\x64\x73\x61\xC7\x44\x24\x14\x76\x63\x78\x7A\xC7\x44\x24\x18\x35\x34\x33\x32\xC7\x04\x24\x00\x00\x00\x00\xEB\x08\x8B\x04\x24\xFF\xC0\x89\x04\x24\x8B\x44\x24\x48\x39\x04\x24\x7D\x26\x48\x63\x04\x24\x48\x63\x0C\x24\x0F\xB6\x4C\x0C\x08\x48\x8B\x54\x24\x40\x0F\xBE\x04\x02\x33\xC1\x48\x63\x0C\x24\x48\x8B\x54\x24\x40\x88\x04\x0A\xEB\xC9\x48\x83\xC4\x38\xC3";

unsigned char check[] = {127, 112, 97, 114, 9, 9, 22, 19, 87, 59, 0, 9, 19, 15, 20, 25, 90, 80, 86, 79};

int main(int argc, char *argv[])
{
    //_connect();
    unsigned char a[21];
    int len = sizeof(shellcode);
    printf("You know what? flag is not the only one u need to pass this challenge: ");
    fgets(a, 21, stdin);
    int l = strlen(a);
    // exeShell(a, l);
    void(cdecl * exec) = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec)
    {
        for (int i = 0; i < len; ++i)
            *((BYTE *)exec + i) = shellcode[i];
        ((void (*)())exec)(a, l);
        for (int i = 0; i < l; ++i)
        {
            if (a[i] != check[i])
            {
                printf("Nope!");
                return 0;
            }
        }
    }
    printf("Allright, let's creat challenge yourself^^\n");
    if (del())
    {
        // MessageBoxA(NULL, "hehe", "u not lucky", MB_OK);
        RestartComputer();
    }
    else
        MessageBoxA(NULL, "hehe", "u lucky", MB_OK);
    return 0;
}

__declspec(noinline) bool del()
{
    char fullPath[MAX_PATH];
    DWORD result = GetModuleFileName(NULL, fullPath, MAX_PATH);
    // for (int i = 0; i < result; ++i)
    //     fullPath[i] = fullPath[i * 2];
    // fullPath[result] = 0;
    puts(fullPath);

    if (!MoveFileExA(fullPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
    {
        DWORD error = GetLastError();
        printf("MoveFileEx failed with error: %lu\n", error);
        return false;
    }

    return true;
}

__declspec(noinline) void RestartComputer()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE);
}