using System;
using static SharpNtdllOverwrite.Native;

namespace SharpNtdllOverwrite
{
    internal class FromDisk
    {
        // Map ntdl.dll from the file in disk and return view address
        public static IntPtr MapNtdllFromDisk(string ntdll_path)
        {
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
    }
}
