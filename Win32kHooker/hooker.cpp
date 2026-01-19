#include "hooker.h"

NtGdiBitBltPtr OriginalNtGdiBitBlt = NULL;
PVOID NtGdiBitBltPtrAddress = NULL;
PEPROCESS GuiProcess = NULL;

fptrW32GetSessionState GetW32GetSessionStateAddr() {
	PVOID win32kBase = GetModuleBase("win32k.sys", NULL);
	if (!win32kBase) {
		return nullptr;
	}
	PVOID pW32pGetSessionState = GetExportAddress(win32kBase, "W32GetSessionState");
	if (!pW32pGetSessionState) {
		return nullptr;
	}
	return (fptrW32GetSessionState)(pW32pGetSessionState);
}

PVOID GetSessionState() {
	fptrW32GetSessionState GetSessionState = (fptrW32GetSessionState)(GetW32GetSessionStateAddr());

	if (!GetSessionState) {
		return nullptr;
	}

	// attach to GUI process
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(GuiProcess, &apcState);
	PVOID output = GetSessionState();
	KeUnstackDetachProcess(&apcState);

	return output;
}

BOOL ResolveWin32kDataPtr(LPCSTR functionName, PDWORD64 DataPtrAddr, PDWORD64 FuncPtr) {
	PVOID Win32kSdt = GetWin32kSdtAddress();
	if (!Win32kSdt) {
		return FALSE;
	}
	PBYTE pFunction = (PBYTE)GetWin32kSyscallRoutine(Win32kSdt, functionName, 0);
	if (!pFunction) {
		return FALSE;
	}
	PVOID SessionStateAddr = GetSessionState();
	if (!SessionStateAddr) {
		return FALSE;
	}
	
#define IS_MOV_DEREF(hs) \
    ((hs).opcode == 0x8B && \
    ((hs).flags & F_MODRM) && \
    (((hs).modrm & 0xC0) != 0xC0))

    // Extract: Check Flag 32 -> return disp32; Else check Flag 8 -> return sign_extended(disp8); Else 0
#define GET_DISP(hs) \
    (((hs).flags & F_DISP32) ? (int32_t)(hs).disp.disp32 : \
    (((hs).flags & F_DISP8)  ? (int32_t)(int8_t)(hs).disp.disp8 : 0))

	// pattern scanning
	//PBYTE DataPtr = (PBYTE)FindPattern(pFunction, 0x50, "\xe8\x00\x00\x00\x00\x4c\x8b\x90\x00\x00\x00\x00\x49\x8b\x82\x00\x00\x00\x00\x48\x8b\x40\x00", "x????xxx????xxx????xxx?");
	hde64s hs{};
    uint8_t* current = pFunction;
    uint8_t* end = current + 0x50;
	DWORD foundOffsets[3] = { 0 };
	BOOL found = FALSE;
	
    while (current < end) {
        unsigned int len = hde64_disasm(current, &hs);
        if (hs.flags & F_ERROR) {
            current++;
            continue;
        }

        // 1. Check for CALL (0xE8)
        if (hs.opcode == 0xE8) {

            uint8_t* scanner = current + len;
            hde64s hs_next;

            int32_t temp_offsets[3] = { 0 };
            bool sequence_match = true;

            // 2. Check for 3 consecutive MOV instructions with dereferences
            for (int i = 0; i < 3; i++) {
                hde64_disasm(scanner, &hs_next);

                if (IS_MOV_DEREF(hs_next)) {
                    foundOffsets[i] = GET_DISP(hs_next);
                    scanner += hs_next.len;
                }
                else {
                    sequence_match = false;
                    break;
                }
            }

            // 3. Check for TEST (0x85)
            if (sequence_match) {
                hde64_disasm(scanner, &hs_next);
                if (hs_next.opcode == 0x85) {
					found = TRUE;
					break;
				}
				else {
					// reset foundOffsets
					memset(foundOffsets, 0, sizeof(foundOffsets));
				}
            }
        }

        current += len;
    }

#undef IS_MOV_DEREF
#undef GET_DISP

	if (DataPtrAddr) *DataPtrAddr = (*(PDWORD64)(*(PDWORD64)((DWORD64)SessionStateAddr + foundOffsets[0]) + foundOffsets[1]) + foundOffsets[2]);
	if (FuncPtr) *FuncPtr = (DWORD64)(*(PDWORD64)(*(PDWORD64)(*(PDWORD64)((DWORD64)SessionStateAddr + foundOffsets[0]) + foundOffsets[1]) + foundOffsets[2]));

	return found;
}

BOOL HookedNtGdiBitBlt(
	HDC hdcDst,
	INT x,
	INT y,
	INT cx,
	INT cy,
	HDC hdcSrc,
	INT xSrc,
	INT ySrc,
	DWORD rop4,
	DWORD crBackColor,
	FLONG fl
) {
	DbgPrintEx(0, 0, "[*] NtGdiBitBlt hook function called!\n");
	// Call the original function
	return OriginalNtGdiBitBlt(
		hdcDst,
		x,
		y,
		cx,
		cy,
		hdcSrc,
		xSrc,
		ySrc,
		rop4,
		crBackColor,
		fl
	);
}

BOOL InitializeHooker() {
	GuiProcess = FindGUIProcess();
	if (!GuiProcess) {
		DbgPrintEx(0, 0, "[-] Failed to find GUI process!\n");
		return FALSE;
	}
	DWORD64 pSessionState = (DWORD64)GetSessionState();
	if (!pSessionState) {
		DbgPrintEx(0, 0, "[-] Failed to get Session State address!\n");
		return FALSE;
	}

	if (!ResolveWin32kDataPtr("NtGdiBitBlt", (PDWORD64)&NtGdiBitBltPtrAddress, (PDWORD64)&OriginalNtGdiBitBlt)) {
		DbgPrintEx(0, 0, "[-] Failed to resolve NtGdiBitBlt pointer!\n");
		return FALSE;
	}

	DbgPrintEx(0, 0, "[+] Data pointer address : 0x%p, NtGdiBitBlt function pointer address : 0x%p. Hooking...\n", NtGdiBitBltPtrAddress, OriginalNtGdiBitBlt);

	*(PDWORD64)NtGdiBitBltPtrAddress = (DWORD64)HookedNtGdiBitBlt;

	DbgPrintEx(0, 0, "[+] NtGdiBitBlt hooked successfully!\n");
	
	return TRUE;
}

BOOL RemoveHooker() {
	if (NtGdiBitBltPtrAddress && OriginalNtGdiBitBlt) {
		*(PDWORD64)NtGdiBitBltPtrAddress = (DWORD64)OriginalNtGdiBitBlt;
		DbgPrintEx(0, 0, "[+] NtGdiBitBlt hook removed successfully!\n");
		return TRUE;
	}
	return FALSE;
}