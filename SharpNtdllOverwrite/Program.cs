using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using static SharpNtdllOverwrite.Native;
using static SharpNtdllOverwrite.FromDisk;
using static SharpNtdllOverwrite.FromKnownDlls;

namespace SharpNtdllOverwrite
{
    internal class SharpNtdllOverwriteProgram
    {
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


        static int[] GetTextSectionInfo(IntPtr ntdl_address)
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
            // Clean DLL - DISK
            string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
            IntPtr unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
            Console.WriteLine("[+] Mapped Ntdll Handle: \t\t\t0x" + unhookedNtdllHandle.ToString("X"));

            int offset_mappeddll = 4096;
            IntPtr unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
            Console.WriteLine("[+] Mapped Ntdll Text Section [Disk]: \t\t0x" + unhookedNtdllTxt.ToString("X"));
            

            // Clean DLL - KNOWNDLLS
            IntPtr unhookedNtdllHandle___2 = MapNtdllFromKnownDlls();
            int offset_mappeddll___2 = 4096;
            IntPtr unhookedNtdllTxt___2 = unhookedNtdllHandle___2 + offset_mappeddll___2;
            Console.WriteLine("[+] Mapped Ntdll Text Section [KnownDlls]: \t0x" + unhookedNtdllTxt___2.ToString("X"));

            
            // Local DLL
            IntPtr localNtdllHandle = auxGetModuleHandle("ntdll.dll");
            Console.WriteLine("[+] Local Ntdll Handle: \t\t\t0x" + localNtdllHandle.ToString("X"));

            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("[+] Local Ntdll Text Section: \t\t\t0x" + localNtdllTxt.ToString("X"));


            // Replace DLL
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);

            Console.ReadKey();

        }
    }
}
