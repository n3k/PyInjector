import unittest
import os
from Injector import GenericInjector, CreateRemoteThreadInjection, InjectorException

class TestInjector(unittest.TestCase):

    def test_instantiation(self):
        target_dll =  "\\".join([os.path.expandvars("%windir%"), "system32", "kernel32.dll"])
        instance = CreateRemoteThreadInjection(1, target_dll)
        self.assert_(True)

    def test_instantiation_fail(self):
        target_dll =  "\\".join([os.path.expandvars("%windir%"), "system32", "non_existent1.dll"])
        try:
            instance = CreateRemoteThreadInjection(1, target_dll)
            self.assert_(False)
        except InjectorException:
            self.assert_(True)

    def test_get_binary_type_x86(self):
        filename = "../Testing/msgbox_x86.dll"
        self.assertEquals("x86", GenericInjector.get_binary_type(filename))

    def test_get_binary_type_x64(self):
        filename = "../Testing/msgbox_x64.dll"
        self.assertEquals("x64", GenericInjector.get_binary_type(filename))

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestInjector)
    unittest.TextTestRunner().run(suite)
