using System;
using static SharpNtdllOverwrite.Native;

namespace SharpNtdllOverwrite
{
    internal class FromKnownDlls
    {
        // Map ntdl.dll from the file in KnownDlls folder and return view address
        public static IntPtr MapNtdllFromKnownDlls() {
            // Initialize OBJECT_ATTRIBUTES struct
            string dll_name = "\\KnownDlls\\ntdll.dll";
            // If 32-bit process the path changes
            if (IntPtr.Size == 4)
            {
                dll_name = "\\KnownDlls32\\ntdll.dll";
            }
            OBJECT_ATTRIBUTES object_attribute = InitializeObjectAttributes(dll_name, OBJ_CASE_INSENSITIVE);

            // NtOpenSection
            IntPtr hSection = IntPtr.Zero;
            uint NtStatus = NtOpenSection(ref hSection, SECTION_MAP_READ, ref object_attribute);
            if (NtStatus != 0)
            {
                Console.WriteLine("[-] Error calling NtOpenSection. NTSTATUS: "+NtStatus.ToString("X"));
                Environment.Exit(0);
            }
            // else { Console.WriteLine("Section object handle: \t" + hSection); }

            // 	MapViewOfFile
            IntPtr pNtdllBuffer = MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling MapViewOfFile");
                Environment.Exit(0);
            }

            // CloseHandle
            bool createfilemapping_ch = CloseHandle(hSection);
            if (!createfilemapping_ch)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }

            return pNtdllBuffer;
        }
    }
}
