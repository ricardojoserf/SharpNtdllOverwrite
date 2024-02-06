using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace SharpNtdllOverwrite
{
    internal class SharpNtdllOverwriteProgram
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFileA(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            uint lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            uint hTemplateFile
        );

        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Int32 WSAGetLastError();

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(
            IntPtr handle
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFileMappingA(
            IntPtr hFile,
            uint lpFileMappingAttributes,
            uint flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            ref uint returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_FILE_HEADER { public UInt16 Machine; public UInt16 NumberOfSections; public UInt32 TimeDateStamp; public UInt32 PointerToSymbolTable; public UInt32 NumberOfSymbols; public UInt16 SizeOfOptionalHeader; public UInt16 Characteristics; }
        // [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { public UInt32 VirtualAddress; public UInt32 Size; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER64 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt64 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt64 SizeOfStackReserve; public UInt64 SizeOfStackCommit; public UInt64 SizeOfHeapReserve; public UInt64 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        }


        protected enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_ACCESS_VIOLATION = 0xC0000005
        }

        const uint GENERIC_READ = (uint)0x80000000; // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/262970b7-cd4a-41f4-8c4d-5a27f0092aaa
        const uint FILE_SHARE_READ = 0x00000001;
        const uint OPEN_EXISTING = 3; // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
        const uint FILE_ATTRIBUTE_NORMAL = (uint)0x00000080; // https://learn.microsoft.com/es-es/windows/win32/fileio/file-attribute-constants
        const uint PAGE_READONLY = 0x02; // https://learn.microsoft.com/es-es/windows/win32/memory/memory-protection-constants
        const uint SEC_IMAGE_NO_EXECUTE = 0x11000000; // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-createfilemappinga
        const uint FILE_MAP_READ = 4; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        // Map ntdl.dll and return view address
        static IntPtr MapNtdllFromDisk()
        {
            // string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
            string ntdll_path = "C:\\Users\\ricardo\\Desktop\\ntdll_poc.dll";

            IntPtr hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

            // CreateFileA
            if (hFile == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling CreateFileA");
                Environment.Exit(0);
            }
            // else{ Console.WriteLine("[+] File handle (CreateFileA): \t\t\t" + hFile); }

            // 	CreateFileMappingA
            IntPtr hSection = CreateFileMappingA(hFile, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, "");
            if (hSection == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling CreateFileMappingA");
                Environment.Exit(0);
            }
            // else{ Console.WriteLine("[+] Mapping handle (CreateFileMappingA): \t" + hSection); }

            // 	MapViewOfFile
            IntPtr pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling MapViewOfFile");
                Environment.Exit(0);
            }
            //else{ Console.WriteLine("[+] View address (MapViewOfFile): \t\t0x" + pNtdllBuffer.ToString("x")); }

            // CloseHandle
            bool createfile_ch = CloseHandle(hFile);
            bool createfilemapping_ch = CloseHandle(hSection);
            if (!createfile_ch || !createfilemapping_ch)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }
            return pNtdllBuffer;
        }


        unsafe static IntPtr auxGetModuleHandle(String dll_name)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            uint temp = 0;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            int PROCESS_BASIC_INFORMATION_SIZE = 48; // System.Runtime.InteropServices.Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)) = 48
            byte[] pbi_byte_array = new byte[PROCESS_BASIC_INFORMATION_SIZE];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;
                NTSTATUS res = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, (uint)(IntPtr.Size * 6), ref temp);
            }

            // Get PEB Base Address
            IntPtr pebaddress = Marshal.ReadIntPtr(pbi_addr + 0x8);
            // Get Ldr
            IntPtr ldr_pointer = pebaddress + 0x18;
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);
            // Get InInitializationOrderModuleList
            IntPtr InInitializationOrderModuleList = ldr_adress + 0x30;

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                dll_base = Marshal.ReadIntPtr(next_flink + 0x20);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + 0x50);
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }

            return IntPtr.Zero;
        }


        static int[] TextSection(IntPtr ntdl_address)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // Check MZ Signature
            byte[] data = new byte[2];
            IntPtr signature_addr = ntdl_address;
            ReadProcessMemory(hProcess, signature_addr, data, data.Length, out _);
            string signature_dos_header = System.Text.Encoding.Default.GetString(data);
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("[-] Incorrect DOS header signature");
                Environment.Exit(0);
            }

            // e_lfanew in offset 0x3C in _IMAGE_DOS_HEADER structure, its size is 4 bytes 
            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            ReadProcessMemory(hProcess, e_lfanew_addr, data, 4, out _);
            int e_lfanew = BitConverter.ToInt32(data, 0);

            // Check PE Signature
            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            ReadProcessMemory(hProcess, image_nt_headers_addr, data, data.Length, out _);
            string signature_nt_header = System.Text.Encoding.Default.GetString(data);
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("[-] Incorrect NT header signature");
                Environment.Exit(0);
            }

            // Check Optional Headers Magic field value
            IntPtr optional_headers_addr = image_nt_headers_addr + 24; // Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) = 24
            data = new byte[4];
            ReadProcessMemory(hProcess, optional_headers_addr, data, data.Length, out _);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            if (optional_header_magic != 0x20B)
            {
                Console.WriteLine("[-] Incorrect Optional Header Magic field value");
                Environment.Exit(0);
            }

            // SizeOfCode
            IntPtr sizeofcode_addr = optional_headers_addr + 4; // Uint16 (2 bytes) + Byte (1 byte) + Byte (1 byte) 
            data = new byte[4];
            ReadProcessMemory(hProcess, sizeofcode_addr, data, data.Length, out _);
            int sizeofcode = BitConverter.ToInt32(data, 0);

            // BaseOfCode
            IntPtr baseofcode_addr = optional_headers_addr + 20; // Uint16 (2 bytes) + 2 Byte (1 byte) + 4 Uint32 (4 byte) - public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode;
            data = new byte[4];
            ReadProcessMemory(hProcess, baseofcode_addr, data, data.Length, out _);
            int baseofcode = BitConverter.ToInt32(data, 0);

            int[] result = { baseofcode, sizeofcode };
            return result;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );


        static void ReplaceNtdllTxtSection(IntPtr unhookedNtdllTxt, IntPtr localNtdllTxt, int localNtdllTxtSize)
        {
            // VirtualProtect to PAGE_EXECUTE_WRITECOPY
            uint dwOldProtection;
            bool vp1_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, out dwOldProtection);
            if (!vp1_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)");
                Environment.Exit(0);
            }

            // Copy from one address to the other
            unsafe
            {
                Console.WriteLine("[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }

            // VirtualProtect back to PAGE_EXECUTE_READ
            bool vp2_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, dwOldProtection, out dwOldProtection);
            if (!vp2_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (PAGE_EXECUTE_READ)");
                Environment.Exit(0);
            }
        }


        static void Main(string[] args)
        {
            IntPtr unhookedNtdllHandle = MapNtdllFromDisk();
            Console.WriteLine("[+] Mapped Ntdll Handle: \t\t\t0x" + unhookedNtdllHandle.ToString("X"));

            int offset_mappeddll = 4096;
            IntPtr unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
            Console.WriteLine("[+] Mapped Ntdll Text Section: \t\t\t0x" + unhookedNtdllTxt.ToString("X"));

            IntPtr localNtdllHandle = auxGetModuleHandle("ntdll.dll"); // FetchLocalNtdllBaseAddress 
            Console.WriteLine("[+] Local Ntdll Handle: \t\t\t0x" + localNtdllHandle.ToString("X"));

            int[] result = TextSection(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            // Console.WriteLine("[+] Base of code: \t\t\t\t0x" + result[0].ToString("X"));
            // Console.WriteLine("[+] Size of code: \t\t\t\t0x" + result[1].ToString("X"));
            Console.WriteLine("[+] Local Ntdll Text Section: \t\t\t0x" + localNtdllTxt.ToString("X"));

            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
        }
    }
}
