from abc import ABCMeta, abstractmethod
import GlobalTypes
from ctypes import c_char_p, c_ulong, POINTER, byref, c_int, c_char
import os
import struct
import sys

class InjectorException(Exception):
    pass

class GenericInjector(object):

    __metaclass__ = ABCMeta

    @staticmethod
    def check_existent_dll(dll):
        return os.path.isfile(dll)

    @staticmethod
    def get_binary_type(filename):

        with open(filename, "rb") as f:
            s = f.read(2)
            if s!="MZ":
                print "Not a PE file"
                return None
            else:
                f.seek(60)
                s = f.read(4)
                header_offset=struct.unpack("<I", s)[0]
                f.seek(header_offset + 4)
                s = f.read(2)
                machine=struct.unpack("<H", s)[0]

                if machine == GlobalTypes.IMAGE_FILE_MACHINE_I386:
                    return GlobalTypes.__X86__
                elif machine == GlobalTypes.IMAGE_FILE_MACHINE_IA64:
                    return GlobalTypes.__IA64__
                elif machine == GlobalTypes.IMAGE_FILE_MACHINE_AMD64:
                    return GlobalTypes.__X64__
                else:
                    print "Unknown architecture"
                    return None

    def __new__(cls, process_id, target_dll):
        if cls.check_existent_dll(target_dll):
            return super(GenericInjector, cls).__new__(cls)
        else:
            raise InjectorException("Target DLL wasn't found!")

    def __init__(self, process_id, target_dll):
        self.process_id = process_id
        self.target_dll = target_dll
        self.kernel32 = GlobalTypes.KERNEL32

    def open_process(self):
        hProcess = self.kernel32.OpenProcess(GlobalTypes.PROCESS_ALL_ACCESS,
                                             0,
                                             self.process_id)
        if hProcess == 0:
            raise InjectorException("OpenProcess failed!, Check PID and Privileges")
        return hProcess

    def get_module_handle(self, module_name):
        hModule = self.kernel32.GetModuleHandleA(module_name)
        if hModule == 0:
            raise InjectorException("GetModuleHandleA failed on %s!" % module_name)
        return hModule

    def wait_for_single_object(self, hObj):
        self.kernel32.WaitForSingleObject(hObj, GlobalTypes.INFINITE)

    def virtual_free_ex(self, hProcess, lpAddr):
        self.kernel32.VirtualFreeEx(hProcess, lpAddr, 0, GlobalTypes.MEM_RELEASE)

    def virtual_free(self, lpAddr):
        self.kernel32.VirtualFreeEx(lpAddr, 0, GlobalTypes.MEM_RELEASE)

    def virtual_alloc_ex(self, hProcess, size):
        lpBuffer = self.kernel32.VirtualAllocEx(hProcess,
                                                   0,
                                                   size,
                                                   GlobalTypes.MEM_COMMIT|GlobalTypes.MEM_RESERVE,
                                                   GlobalTypes.PROCESS_EXECUTE_READWRITE)
        print "Allocated address: %16x" % lpBuffer
        if lpBuffer == 0:
            self.virtual_free_ex(hProcess, lpBuffer)
            raise InjectorException("VirtualAlloxEx failed!. Couldn't map memory in remote process")
        return lpBuffer

    def virtual_alloc(self, size):
        lpBuffer = self.kernel32.VirtualAlloc(c_int(0),
                                        c_int(size),
                                        GlobalTypes.MEM_COMMIT|GlobalTypes.MEM_RESERVE,
                                        GlobalTypes.PROCESS_EXECUTE_READWRITE)

        print "Allocated address: %08x" % lpBuffer
        if lpBuffer == 0:
            self.virtual_free(lpBuffer)
            raise InjectorException("VirtualAllox failed!. Couldn't map memory in process")
        return lpBuffer


    def write_process_memory(self, hProcess, lpBaseAddress, lpBuffer, nSize):
        count = GlobalTypes.SIZE_T(0)
        writeResult = self.kernel32.WriteProcessMemory(hProcess,
                                                       lpBaseAddress,
                                                       lpBuffer,
                                                       nSize + 2,
                                                       byref(count))

        if writeResult == 0:
            print "Error: %08x" % self.kernel32.GetLastError()
            self.virtual_free_ex(hProcess, lpBaseAddress)
            raise InjectorException("WriteProcessMemory failed!")
        return count.value


    def close_handle(self, handle):
        self.kernel32.CloseHandle(handle)

    @abstractmethod
    def performInjection(self):
        pass


class WoW64CrossInjection(GenericInjector):

    TARGET_PROCESS = GlobalTypes.__X64__

    LOAD_CUSTOM_DLL_SHELLCODE = ""
    LOAD_CUSTOM_DLL_SHELLCODE += "\x41\x50\x41\x51\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x48\x8B\x40\x18\x48\x8B\x40\x30\x48\x8B\x00\x48\x8B"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x00\x4C\x8B\x40\x10\x4D\x31\xC9\x41\xB9\x8E\x4E\x0E"
    LOAD_CUSTOM_DLL_SHELLCODE += "\xEC\xE8\x0F\x00\x00\x00\x51\xFF\xD0\x48\x83\xC4\x08"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x41\x59\x41\x58\x48\x31\xC0\xC3\x57\x51\x53\x52\x48"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x31\xDB\x48\x31\xC9\x48\x31\xFF\x41\x8B\xB8\x3C\x00"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x00\x00\x41\x8B\xBC\x38\x88\x00\x00\x00\x4C\x01\xC7"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x8B\x8F\x18\x00\x00\x00\x8B\x9F\x20\x00\x00\x00\x4C"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x01\xC3\x48\x85\xC9\x74\x52\x48\xFF\xC9\x8B\xB4\x8B"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x00\x00\x00\x00\x4C\x01\xC6\x48\x31\xD2\x48\x31\xC0"
    LOAD_CUSTOM_DLL_SHELLCODE += "\xFC\xAC\x84\xC0\x74\x07\xC1\xCA\x0D\x01\xC2\xEB\xF4"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x44\x39\xCA\x75\xD6\x8B\x97\x24\x00\x00\x00\x4C\x01"
    LOAD_CUSTOM_DLL_SHELLCODE += "\xC2\x8B\x8C\x4A\x00\x00\x00\x00\x81\xE1\xFF\xFF\x00"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x00\x8B\x97\x1C\x00\x00\x00\x4C\x01\xC2\x8B\x84\x8A"
    LOAD_CUSTOM_DLL_SHELLCODE += "\x00\x00\x00\x00\x4C\x01\xC0\x5A\x5B\x59\x5F\xC3"


    WOW64Injector = ""
    WOW64Injector += "\x53\x51\xE8\x03\x00\x00\x00"
    WOW64Injector += "\x59\x5B\xC3\xEB\x16\x59\xEB\x0D\x5B\x31\xC0\x50\x6A\x23"
    WOW64Injector += "\x50\x53\x6A\x33\x51\x48\xCB\xE8\xEE\xFF\xFF\xFF\xC3\xE8"
    WOW64Injector += "\xE5\xFF\xFF\xFF\x55\x56\x57\x52\x41\x50\x41\x51\x41\x52"
    WOW64Injector += "\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x65\x48\x8B\x04"
    WOW64Injector += "\x25\x60\x00\x00\x00\x48\x8B\x40\x18\x48\x8B\x40\x30\x48"
    WOW64Injector += "\x8B\x40\x10\x49\x89\xC0\x4D\x31\xC9\x41\xB9\x41\x20\x2F"
    WOW64Injector += "\x44\xE8\x72\x00\x00\x00\x48\x31\xC9\x48\xB9__HPROCESS__"
    WOW64Injector += "\x00\x00\x00\x00\x48\x31\xD2\x4D\x31\xC0\x4D\x31\xC9"
    WOW64Injector += "\x48\x83\xEC\x68\x4C\x89\x4C\x24\x20\x4C\x89\x4C\x24\x28"
    WOW64Injector += "\x48\xBB__SHELLCODE_ADDRESS__\x00\x00\x00\x00\x48\x89\x5C\x24"
    WOW64Injector += "\x30\x48\xBB__DLL_ADDRESS__\x00\x00\x00\x00\x48\x89\x5C"
    WOW64Injector += "\x24\x38\x48\xBB__HTHREAD__\x00\x00\x00\x00\x48\x89"
    WOW64Injector += "\x5C\x24\x40\x4C\x89\x4C\x24\x48\xFF\xD0\x48\x83\xC4\x68"
    WOW64Injector += "\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59"
    WOW64Injector += "\x41\x58\x5A\x5F\x5E\x5D\x48\xCB\x57\x51\x53\x52\x48\x31"
    WOW64Injector += "\xDB\x48\x31\xC9\x48\x31\xFF\x41\x8B\xB8\x3C\x00\x00\x00"
    WOW64Injector += "\x41\x8B\xBC\x38\x88\x00\x00\x00\x4C\x01\xC7\x8B\x8F\x18"
    WOW64Injector += "\x00\x00\x00\x8B\x9F\x20\x00\x00\x00\x4C\x01\xC3\x48\x85"
    WOW64Injector += "\xC9\x74\x52\x48\xFF\xC9\x8B\xB4\x8B\x00\x00\x00\x00\x4C"
    WOW64Injector += "\x01\xC6\x48\x31\xD2\x48\x31\xC0\xFC\xAC\x84\xC0\x74\x07"
    WOW64Injector += "\xC1\xCA\x0D\x01\xC2\xEB\xF4\x44\x39\xCA\x75\xD6\x8B\x97"
    WOW64Injector += "\x24\x00\x00\x00\x4C\x01\xC2\x8B\x8C\x4A\x00\x00\x00\x00"
    WOW64Injector += "\x81\xE1\xFF\xFF\x00\x00\x8B\x97\x1C\x00\x00\x00\x4C\x01"
    WOW64Injector += "\xC2\x8B\x84\x8A\x00\x00\x00\x00\x4C\x01\xC0\x5A\x5B\x59"
    WOW64Injector += "\x5F\xC3"

    def __init__(self, process_id, target_dll):
        super(WoW64CrossInjection, self).__init__(process_id, target_dll)

    def _run_injector(self):

        ptr = self.virtual_alloc(len(self.WOW64Injector))

        buf = (c_char * len(self.WOW64Injector)).from_buffer(bytearray(self.WOW64Injector))

        self.kernel32.RtlMoveMemory(c_int(ptr),
                                    buf,
                                    c_int(len(self.WOW64Injector)))

        ht = self.kernel32.CreateThread(c_int(0),
                                         c_int(0),
                                         c_int(ptr),
                                         c_int(0),
                                         c_int(0),
                                         byref(c_int(0)))

        self.wait_for_single_object(ht)
        self.close_handle(ht)


    def performInjection(self):

        hProcess = self.open_process()

        # Write DLL name into the target process memory
        dll_address = self.virtual_alloc_ex(hProcess, 256)
        lpBuffer = c_char_p(self.target_dll)
        bytes_written = self.write_process_memory(hProcess, dll_address, lpBuffer, len(self.target_dll))
        print "%d bytes were written into the target process memory" % bytes_written

        # Write the stage shellcode into the target process memory
        shellcode_address = self.virtual_alloc_ex(hProcess, len(self.LOAD_CUSTOM_DLL_SHELLCODE))
        lpBuffer = c_char_p(self.LOAD_CUSTOM_DLL_SHELLCODE)
        bytes_written = self.write_process_memory(hProcess, shellcode_address, lpBuffer, len(self.LOAD_CUSTOM_DLL_SHELLCODE))
        print "%d bytes were written into the target process memory" % bytes_written

        # hack???
        hRemoteThread = GlobalTypes.HANDLE(0)
        a = byref(hRemoteThread) #a = "<cparam 'P' (027664B8)>"
        a = str(a)
        l = a.find("(") + 1
        r = a.find(")")
        val = int(a[l:r] , 16)

        # Patch the Injector with the proper target values
        self.WOW64Injector = self.WOW64Injector.replace("__HPROCESS__", struct.pack("<I", hProcess))
        self.WOW64Injector = self.WOW64Injector.replace("__SHELLCODE_ADDRESS__", struct.pack("<I", shellcode_address))
        self.WOW64Injector = self.WOW64Injector.replace("__DLL_ADDRESS__", struct.pack("<I", dll_address))
        self.WOW64Injector = self.WOW64Injector.replace("__HTHREAD__", struct.pack("<I", val))


        self._run_injector()



class CreateRemoteThreadInjection(GenericInjector):

    TARGET_PROCESS = GlobalTypes.__X86__

    def __init__(self, process_id, target_dll):
        super(CreateRemoteThreadInjection, self).__init__(process_id, target_dll)

    def performInjection(self):

        hProcess = self.open_process()
        #hkernel32Module = self.get_module_handle("kernel32.dll")

        remote_addr = self.virtual_alloc_ex(hProcess, 256)
        lpBuffer = c_char_p(self.target_dll)
        bytes_written = self.write_process_memory(hProcess, remote_addr, lpBuffer, len(self.target_dll))

        print "%d bytes were written into the target process memory" % bytes_written

        hRemoteThread = self.kernel32.CreateRemoteThread(hProcess,
                                                         None,
                                                         0,
                                                         self.kernel32.LoadLibraryA,
                                                         remote_addr,
                                                         0,
                                                         byref(c_ulong(0)))

        self.wait_for_single_object(hRemoteThread)

        print "Handle Remote Thread: %08x" % hRemoteThread
        print "Error: %08x" % self.kernel32.GetLastError()


        self.virtual_free_ex(hProcess, remote_addr)
        self.close_handle(hRemoteThread)
        self.close_handle(hProcess)


class RtlCreateUserThreadInjection(GenericInjector):

    TARGET_PROCESS = GlobalTypes.__X86__

    def __init__(self, process_id, target_dll):
        super(RtlCreateUserThreadInjection, self).__init__(process_id, target_dll)
        self.ntdll = GlobalTypes.NTDLL

    def performInjection(self):

        hProcess = self.open_process()

        #hkernel32Module = self.get_module_handle("kernel32.dll")

        remote_addr = self.virtual_alloc_ex(hProcess, 256)
        lpBuffer = c_char_p(self.target_dll)
        bytes_written = self.write_process_memory(hProcess, remote_addr, lpBuffer, len(self.target_dll))

        print "%d bytes were written into the target process memory" % bytes_written

        hRemoteThread = GlobalTypes.HANDLE(0)

        self.ntdll.RtlCreateUserThread( hProcess,
                                        None,
                                        False,
                                        0,
                                        None,
                                        None,
                                        self.kernel32.LoadLibraryA,
                                        remote_addr,
                                        byref(hRemoteThread),
                                        None
                                       )

        self.wait_for_single_object(hRemoteThread)

        print "Handle Remote Thread: %08x" % hRemoteThread.value
        print "Error: %08x" % self.kernel32.GetLastError()

        self.virtual_free_ex(hProcess, remote_addr)
        self.close_handle(hRemoteThread)
        self.close_handle(hProcess)


class InjectorStrategy(GenericInjector):

    def __init__(self, process_id, target_dll):
        super(InjectorStrategy, self).__init__(process_id, target_dll)
        self.injectors = [CreateRemoteThreadInjection, RtlCreateUserThreadInjection, WoW64CrossInjection]

    def performInjection(self):
        """
        Determines the source DLL PE type to select the proper injector
        """
        binary_type = self.get_binary_type(self.target_dll)
        for injector_cls in self.injectors:
            if injector_cls.TARGET_PROCESS == binary_type:
                print "Selected Injector: %s" % injector_cls.__name__
                injector = injector_cls(self.process_id, self.target_dll)
                injector.performInjection()
                break


def run_injection_test():
    target_dll = os.getcwd() + "\\Testing\\msgbox_x64.dll"
    if len(sys.argv) < 2:
        print "+] Usage: %s <target-pid>" % sys.argv[0]
        sys.exit(-1)

    injector = InjectorStrategy(int(sys.argv[1]), target_dll)
    injector.performInjection()


if __name__ == "__main__":
    #run_injection_test()

    target_dll = os.getcwd() + r"\Testing\msgbox_x86.dll"

    if len(sys.argv) < 2:
        print "+] Usage: %s <target-pid>" % sys.argv[0]
        sys.exit(-1)

    injector = InjectorStrategy(int(sys.argv[1]), target_dll)
    injector.performInjection()
