#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <iostream>




VOID CheckJMP(char* name, DWORD* address, int numBytes) {

    BYTE* opcode = (BYTE*)address;
    
    if (!(name[0] == 'N' && name[1] == 't')) {
        return;
    }

    for (int i = 0; i < numBytes; i++) {
        if (*opcode == 0xE9) {
            printf("%s IS HOOKED   --->   ", name);
            printf("jmp detected at opcode: %d\n", i);
           // printf("Next Instruction --> %x\n\n", *(opcode + 1));
            opcode += 1;
        }
    }


}



void ListDLLs() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32);
    printf("[LOADED MODULES]\n");

    if (Module32First(hSnap, &modEntry)) {
        do {
            wprintf(L"%s   --->   %p\n", modEntry.szExePath, modEntry.modBaseAddr);
        } while (Module32Next(hSnap, &modEntry));
    }



}


void DumpExports(HMODULE hLib, void* lib, int numBytes) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lib;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)lib + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lib + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* name = (DWORD*)((BYTE*)lib + export_dir->AddressOfNames);

    for (int i = 0; i < export_dir->NumberOfNames; i++) {

      //  printf("CALLING %d\n", i);
        CheckJMP((char*)lib + name[i], (DWORD*)GetProcAddress(hLib, (LPCSTR)((BYTE*)lib + name[i])), numBytes);
    }

}






int main(int argc, char* argv[])
{

    if (argc < 3) {
        printf("USAGE   --->   hookFinder.exe [DLL Name] [# of bytes to scan per function]\n");
        exit(-1);
    }


    printf("\n\n");

    CHAR* dll = argv[1]; // DLL to check for hooks
    HANDLE hDLL = LoadLibraryA(dll);
    HMODULE hMod = GetModuleHandleA(dll);
    int numBytes = atoi(argv[2]);

    printf("NUMBYTES: %d\n\n", numBytes);




    if (hDLL == NULL) {
        printf("Could not obtain handle to specified DLL\n");
    }

    ListDLLs();

    printf("----------------------------------------------------------------------------------------\n");


    DumpExports(hMod, hDLL, numBytes);
    CloseHandle(hMod);
    CloseHandle(hDLL);

    printf("\n\n[COMPLETED]");
    return 0;


}

