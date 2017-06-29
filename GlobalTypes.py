import ctypes
from ctypes import wintypes, Structure
from ctypes.wintypes import *

PROCESS_ALL_ACCESS = (0x000F0000L | 0x00100000L | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PROCESS_EXECUTE_READWRITE = 0x40
INFINITE = -1
IMAGE_FILE_MACHINE_I386=332
IMAGE_FILE_MACHINE_IA64=512
IMAGE_FILE_MACHINE_AMD64=34404

__X86__ = "x86"
__X64__ = "x64"
__IA64__ = "IA64"

SIZE_T = ctypes.c_size_t
LPSIZE_T = ctypes.POINTER(SIZE_T)
LPDWORD = ctypes.POINTER(DWORD)
WCHAR_SIZE = ctypes.sizeof(WCHAR)
LPSECURITY_ATTRIBUTES = LPVOID
LPTHREAD_START_ROUTINE = LPVOID
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
LPTSTR = ctypes.POINTER(ctypes.c_char)
PHANDLE = ctypes.POINTER(ctypes.c_void_p)

# Structures Definition


KERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True)
NTDLL = ctypes.WinDLL('ntdll', use_last_error=True)

# Exact Type Specification

KERNEL32.OpenProcess.argtypes = (
    DWORD, # dwDesiredAccess
    BOOL,  # bInheritHandle
    DWORD) # dwProcessId

KERNEL32.VirtualAllocEx.restype = wintypes.LPVOID
KERNEL32.VirtualAllocEx.argtypes = (
    HANDLE, # hProcess
    LPVOID, # lpAddress
    SIZE_T,          # dwSize
    DWORD,  # flAllocationType
    DWORD)  # flProtect

KERNEL32.VirtualFreeEx.argtypes = (
    HANDLE, # hProcess
    LPVOID, # lpAddress
    SIZE_T,          # dwSize
    DWORD)  # dwFreeType

KERNEL32.WriteProcessMemory.argtypes = (
    HANDLE,  # hProcess
    LPVOID,  # lpBaseAddress
    LPCVOID, # lpBuffer
    SIZE_T,           # nSize
    LPSIZE_T)         # lpNumberOfBytesWritten _Out_

KERNEL32.CreateRemoteThread.argtypes = (
    HANDLE,        # hProcess
    LPSECURITY_ATTRIBUTES,  # lpThreadAttributes
    SIZE_T,                 # dwStackSize
    LPTHREAD_START_ROUTINE, # lpStartAddress
    LPVOID,        # lpParameter
    DWORD,         # dwCreationFlags
    LPDWORD)       # lpThreadId _Out_

KERNEL32.WaitForSingleObject.argtypes = (HANDLE, # hHandle
                                         DWORD)  # dwMilliseconds

KERNEL32.CloseHandle.argtypes = (HANDLE,) # hObject


NTDLL.RtlCreateUserThread.argtypes = (HANDLE, # ProcessHandle
                                      LPVOID, # SecurityDescriptor
                                      BOOL, # CreateSuspended
                                      ULONG, # StackZeroBits
                                      LPDWORD, # StackReserved
                                      LPDWORD, # StackCommit
                                      LPVOID, # StartAddress
                                      LPVOID, # StartParameter
                                      LPVOID, # ThreadHandle
                                      LPVOID) # ClientID

