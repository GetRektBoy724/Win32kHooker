# Win32kHooker

Win32kHooker is a Windows Kernel Driver that demonstrates how to locate and hook functions within `win32k.sys`.

Because `win32k.sys` is a session-space driver, it is not mapped into the system address space of every process. This driver overcomes this limitation by locating a GUI-capable process (e.g., `winlogon.exe`) and attaching to its address space to safely modify `win32k` memory.

## Mechanism

1.  **Process Identification**: Scans active processes to find `winlogon.exe`, which guarantees `win32k.sys` mapping.
2.  **Context Attachment**: Uses `KeStackAttachProcess` to switch the thread context to the target process.
3.  **Address Resolution**:
    *   Resolves the `W32GetSessionState` export.
    *   Locates `NtGdiBitBlt` by verifying syscall numbers in `win32u.dll` and the shadow SSDT.
4.  **Hook Implementation**: Utilizes the Hde64 disassembler to locate internal dispatch pointers within the target function and performs a pointer swap.

## Technical Distinction

This project addresses architectural changes in modern Windows versions compared to older `win32k` implementations.

*   **Legacy vs. Modern Storage**: Older versions of `win32k.sys` typically stored function pointers in global variables within the `.data` section. Newer versions, however, have moved these pointers into opaque session state structures.
*   **Dynamic Resolution**: Consequently, simple global pattern scans are no longer sufficient. This driver resolves the hook target relative to `W32GetSessionState`. It uses runtime disassembly to parse the `NtGdiBitBlt` instruction stream, dynamically extracting the exact offsets needed to traverse these opaque structures and locate the function pointer.

## Build Requirements

*   Visual Studio 2019 or later
*   Windows Driver Kit (WDK)

## Usage

1.  Enable test signing on the target machine:
    ```bash
    bcdedit /set testsigning on
    ```
2.  Build the solution in **Release/x64** configuration.
3.  Install and start the driver using the Service Control Manager:
    ```bash
    sc create Win32kHooker type= kernel binPath= "C:\path\to\Win32kHooker.sys"
    sc start Win32kHooker
    ```
4.  View hook output using a kernel debugger or DebugView.
