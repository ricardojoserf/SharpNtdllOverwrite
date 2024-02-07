using System;
using System.Runtime.InteropServices;
using static SharpNtdllOverwrite.Native;

namespace SharpNtdllOverwrite
{
    internal class FromKnownDlls
    {

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtOpenSection(
            ref IntPtr FileHandle,
            int DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes
        );

        // https://learn.microsoft.com/en-us/answers/questions/262095/read-file-from-my-computer-using-c
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Buffer;
        }

        // Source: https://learn.microsoft.com/en-us/answers/questions/262095/read-file-from-my-computer-using-c
        public static OBJECT_ATTRIBUTES InitializeObjectAttributes(UNICODE_STRING objectName, UInt32 Attributes)
        {
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.RootDirectory = IntPtr.Zero;
            // objectAttributes.ObjectName = objectName
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, objectAttributes.ObjectName, false);
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;
            objectAttributes.Attributes = Attributes;
            objectAttributes.Length = Convert.ToUInt32(Marshal.SizeOf(objectAttributes));
            return objectAttributes;
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
        

        [DllImport("NtDll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, IntPtr SourceString);

        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int SECTION_MAP_READ = 0x0004; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win


        public static IntPtr MapNtdllFromKnownDlls() {
            // Initialize OBJECT_ATTRIBUTES struct
            UNICODE_STRING RootDirectoryName = new UNICODE_STRING();
            string sBuffer = "\\KnownDlls\\ntdll.dll";
            IntPtr pBuffer = Marshal.StringToHGlobalUni(sBuffer);
            RtlInitUnicodeString(ref RootDirectoryName, pBuffer);
            OBJECT_ATTRIBUTES object_attribute = InitializeObjectAttributes(RootDirectoryName, OBJ_CASE_INSENSITIVE);

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
