using System;
using static SharpNtdllOverwrite.Program;
using static SharpNtdllOverwrite.Native;


namespace SharpNtdllOverwrite
{
    internal class FromDebugProc
    {
        public unsafe static IntPtr MapNtdllFromDebugProc(string process_path)
        {
            // CreateProcess in DEBUG mode
            STARTUPINFO si = new STARTUPINFO();
            si.cb = System.Runtime.InteropServices.Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool createprocess_res = CreateProcess(process_path, null, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi);
            if (!createprocess_res) {
                Console.WriteLine("[-] Error calling CreateProcess");
                Environment.Exit(0);
            }
            // Console.WriteLine("[+] Process created with PID:\t\t\t" + pi.dwProcessId);

            // Ntdll address and size from local process
            IntPtr localNtdllHandle = auxGetModuleHandle("ntdll.dll");
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtSize = result[1];

            // ReadProcessMemory to copy the bytes from ntdll.dll in the suspended process into a new buffer (ntdllBuffer)
            byte[] ntdllBuffer = new byte[localNtdllTxtSize];
            // IntPtr debugged_process_ntdll_handle = localNtdllHandle;
            uint readprocmem_res = ReadProcessMemory(pi.hProcess, localNtdllHandle, ntdllBuffer, ntdllBuffer.Length, out _);
            if (readprocmem_res == 0)
            {
                Console.WriteLine("[-] Error calling ReadProcessMemory");
                Environment.Exit(0);
            }

            IntPtr pNtdllBuffer = IntPtr.Zero;
            fixed (byte* p = ntdllBuffer)
            {
                pNtdllBuffer = (IntPtr)p;
            }

            // Terminate and close handles in debug process
            bool debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
            bool terminateproc_res = TerminateProcess(pi.hProcess, 0);
            if (debugstop_res == false || terminateproc_res == false) {
                Console.WriteLine("[-] Error calling DebugActiveProcessStop or TerminateProcess");
                Environment.Exit(0);
            }
            bool closehandle_proc = CloseHandle(pi.hProcess);
            bool closehandle_thread = CloseHandle(pi.hThread);
            if (!closehandle_proc || !closehandle_thread)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }

            return pNtdllBuffer;
        }
    }
}
