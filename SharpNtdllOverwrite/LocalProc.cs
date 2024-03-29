﻿using System;
using System.Runtime.InteropServices;
using static SharpNtdllOverwrite.Win32;

namespace SharpNtdllOverwrite
{
    internal class LocalProc
    {
        public unsafe static IntPtr CustomGetModuleHandle(String dll_name)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            // If 32-bit process these offsets change
            if (IntPtr.Size == 4)
            {
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
            }

            // Get current process handle
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;
                NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out _);
                /// Console.WriteLine("[+] Process_Basic_Information Address: \t\t0x" + pbi_addr.ToString("X"));
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            /// Console.WriteLine("[+] PEB Address Pointer:\t\t\t0x" + peb_pointer.ToString("X"));
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            /// Console.WriteLine("[+] PEB Address:\t\t\t\t0x" + pebaddress.ToString("X"));

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);
            /// Console.WriteLine("[+] LDR Pointer:\t\t\t\t0x" + ldr_pointer.ToString("X"));
            /// Console.WriteLine("[+] LDR Address:\t\t\t\t0x" + ldr_adress.ToString("X"));

            // Get InInitializationOrderModuleList (LIST_ENTRY) inside _PEB_LDR_DATA struct
            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            /// Console.WriteLine("[+] InInitializationOrderModuleList:\t\t0x" + InInitializationOrderModuleList.ToString("X"));

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = Marshal.ReadIntPtr(next_flink + flink_dllbase_offset);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + flink_buffer_offset);
                // Get DLL name from buffer address
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);

                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }

            return IntPtr.Zero;
        }


        public static int[] GetTextSectionInfo(IntPtr ntdl_address)
        {
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

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
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
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
    }
}
