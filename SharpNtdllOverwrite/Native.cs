using System;
using System.Runtime.InteropServices;
using static SharpNtdllOverwrite.FromDebugProc;

namespace SharpNtdllOverwrite
{
    class Native
    {
        //////////////////// FUNCTIONS //////////////////// 
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            uint lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            uint hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 WSAGetLastError();

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr handle
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileMappingA(
            IntPtr hFile,
            uint lpFileMappingAttributes,
            uint flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            ref uint returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            // out IntPtr lpNumberOfBytesRead
            out uint lpNumberOfBytesRead
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtOpenSection(
            ref IntPtr FileHandle,
            int DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes
        );

        // Source: https://learn.microsoft.com/en-us/answers/questions/262095/read-file-from-my-computer-using-c
        public static OBJECT_ATTRIBUTES InitializeObjectAttributes(string dll_name, UInt32 Attributes)
        {
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.RootDirectory = IntPtr.Zero;
            // ObjectName
            UNICODE_STRING objectName = new UNICODE_STRING();
            objectName.Buffer = dll_name; // Marshal.StringToHGlobalUni(str);
            objectName.Length = (ushort)(dll_name.Length * 2);
            objectName.MaximumLength = (ushort)(dll_name.Length * 2 + 2);
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, objectAttributes.ObjectName, false);
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;
            objectAttributes.Attributes = Attributes;
            objectAttributes.Length = Convert.ToUInt32(Marshal.SizeOf(objectAttributes));
            return objectAttributes;
        }


        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess
        (
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll")]
        public static extern bool DebugActiveProcessStop(int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);


        ///////////////////// STRUCTS ///////////////////// 
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
            // public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }


        /////////////////////  ENUMS  /////////////////////
        public enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_ACCESS_VIOLATION = 0xC0000005
        }

        /* 
        //For future reference
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_FILE_HEADER { public UInt16 Machine; public UInt16 NumberOfSections; public UInt32 TimeDateStamp; public UInt32 PointerToSymbolTable; public UInt32 NumberOfSymbols; public UInt16 SizeOfOptionalHeader; public UInt16 Characteristics; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { public UInt32 VirtualAddress; public UInt32 Size; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER64 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt64 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt64 SizeOfStackReserve; public UInt64 SizeOfStackCommit; public UInt64 SizeOfHeapReserve; public UInt64 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_NT_HEADERS{ public UInt32 Signature; public IMAGE_FILE_HEADER FileHeader; public IMAGE_OPTIONAL_HEADER64 OptionalHeader64; }
        */
        
        
        //////////////////// CONSTANTS ////////////////////
        public const uint GENERIC_READ = (uint)0x80000000; // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/262970b7-cd4a-41f4-8c4d-5a27f0092aaa
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3; // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
        public const uint FILE_ATTRIBUTE_NORMAL = (uint)0x00000080; // https://learn.microsoft.com/es-es/windows/win32/fileio/file-attribute-constants
        public const uint PAGE_READONLY = 0x02; // https://learn.microsoft.com/es-es/windows/win32/memory/memory-protection-constants
        public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000; // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-createfilemappinga
        public const uint FILE_MAP_READ = 4; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int SECTION_MAP_READ = 0x0004; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint DEBUG_PROCESS = 0x00000001;
    }
}
