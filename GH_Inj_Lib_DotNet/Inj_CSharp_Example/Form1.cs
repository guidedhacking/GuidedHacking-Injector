using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using GH_Inj_Lib_DotNet;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Inj_CSharp_Example
{
    public partial class Form1 : Form
    {

        #region "Pinvoke"

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        #endregion

        #region "Declares"

        public bool Is64OS = Environment.Is64BitOperatingSystem;

        private List<object> INJECTION_MODE_TypeList = Enum.GetValues(typeof(GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE)).Cast<object>().ToList();
        private List<object> LAUNCH_METHOD_TypeList = Enum.GetValues(typeof(GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD)).Cast<object>().ToList();
        private List<object> DLLOptions_TypeList = Enum.GetValues(typeof(GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx)).Cast<object>().ToList();
        private List<object> ManualMapOptions_TypeList = Enum.GetValues(typeof(GH_Inj_Lib_DotNet.Core.GHWrapper.ManualMapping)).Cast<object>().ToList();
        private List<object> CloakOptions_TypeList = Enum.GetValues(typeof(GH_Inj_Lib_DotNet.Core.GHWrapper.ThreadCreationOptions)).Cast<object>().ToList();

        #endregion


        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            StartRuntimes();
        }

        private void Form1_Shown(object sender, EventArgs e)
        {
            InitializeEngines();
        }

        #region "UI"


        private void InitializeEngines()
        {
            GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq ArqHelper = GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq.x86;

            // This will change it depending on your needs.
            // If your Then compilation Is X86, you must place X86 And vice versa.

            // In the event that your compilation Is Any CPU, you must uncheck 'prefer 32 bits' if it is for x64 and vice versa.

            // ''''''''''''''''''''''''''
            // Extracting Wrapper
            // ''''''''''''''''''''''''''

            try
            {
                GH_Inj_Lib_DotNet.Core.HelperExtractor.Extract(ArqHelper);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK);
                Environment.Exit(0);
            }

            // ''''''''''''''''''''''''''
            // Load Wrapper
            // ''''''''''''''''''''''''''

            IntPtr InjHelperLoadResult = LoadLibrary(GH_Inj_Lib_DotNet.Core.GHWrapper.API);

            if (InjHelperLoadResult == IntPtr.Zero)
            {
                // This usually happens because it is trying to load core.helperextractor.arq.x64 in a 32bits system.
                MessageBox.Show("The Wrapper could not be loaded, check if the coinside destination architecture.", "Error", MessageBoxButtons.OK);
                Environment.Exit(0);
            }

            // ''''''''''''''''''''''''''
            // Load GH Injection Library
            // ''''''''''''''''''''''''''

            string EngineDLL = string.Empty;

            switch (ArqHelper)
            {
                case GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq.x86:
                {
                        EngineDLL = "GH Injector - x86.dll";
                        break;
                }

                case GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq.x64:
                {
                        EngineDLL = "GH Injector - x64.dll";
                        break;
                }
            }

            IntPtr LoadResult = LoadLibrary(EngineDLL);

            if (LoadResult == IntPtr.Zero)
            {
                // This usually happens because it is trying to load core.helperextractor.arq.x64 in a 32bits system.
                MessageBox.Show("Failed to load : " + EngineDLL, "Error", MessageBoxButtons.OK);
                Environment.Exit(0);
            }

            GH_Inj_Lib_DotNet.Core.GHWrapper.SetManualHook(EngineDLL);


            // ''''''''''''''''''''''''''
            // Load Symbols
            // ''''''''''''''''''''''''''

            if (System.IO.Directory.Exists("x86") == false)
                System.IO.Directory.CreateDirectory("x86");
            if (System.IO.Directory.Exists("x64") == false)
                System.IO.Directory.CreateDirectory("x64");

            bool ShowDialog = false;

            if (ArqHelper == GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq.x86)
            {
                if (System.IO.File.Exists(System.IO.Path.Combine("x86", "wntdll.pdb")) == false)
                    ShowDialog = true;
            }
            else if (System.IO.File.Exists(System.IO.Path.Combine("x64", "ntdll.pdb")) == false)
                ShowDialog = true;

            if (ShowDialog == true)
            {
                SymbolsDownloader SymbolDownloader = new SymbolsDownloader();

                SymbolDownloader.EngineDLL = EngineDLL;
                SymbolDownloader.Is64 = (ArqHelper == GH_Inj_Lib_DotNet.Core.HelperExtractor.Arq.x64);

                if (SymbolDownloader.ShowDialog() != DialogResult.OK)
                {
                    MessageBox.Show("He has canceled the download process, you must download the symbols to work.", "Error", MessageBoxButtons.OK);
                    Environment.Exit(0);
                }
            }
        }


        public void StartRuntimes()
        {
            INJECTION_MODECombo.Items.AddRange(INJECTION_MODE_TypeList.ToArray());
            INJECTION_MODECombo.SelectedIndex = 0;

            LAUNCH_METHODCombo.Items.AddRange(LAUNCH_METHOD_TypeList.ToArray());
            LAUNCH_METHODCombo.SelectedIndex = 0;

            DLLOptionsCombo.Items.AddRange(DLLOptions_TypeList.ToArray());
            DLLOptionsCombo.SelectedIndex = 0;
        }


        private void ProcessList_Click(object sender, EventArgs e)
        {
            ListProcess();
        }

        public void ListProcess()
        {
            ProcessList.Items.Clear();
            List<string> ProcShowFormat = new List<string>();
            List<Process> ProcList = Process.GetProcesses().ToList();

            foreach (Process Proc in ProcList)
                ProcShowFormat.Add(string.Format("{0} ({1})", Proc.ProcessName, Proc.Id));

            ProcessList.Items.AddRange(ProcShowFormat.ToArray());
        }

        private void Button2_Click(object sender, EventArgs e)
        {
            if (OpenFileDialog1.ShowDialog() == DialogResult.OK)
                DLL_Path.Text = OpenFileDialog1.FileName;
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            try
            {
                string CurrentSelected = ProcessList.Text;
                if (CurrentSelected == string.Empty)
                    throw new Exception(" Select Process ! ");

                int startIndex = CurrentSelected.IndexOf("(") + 1;
                int length = CurrentSelected.IndexOf(")") - startIndex;
                string ProcessID = CurrentSelected.Substring(startIndex, length);
                string DLLPath = DLL_Path.Text;

                Process TargetProcess = Process.GetProcessById(int.Parse(ProcessID));

                if (TargetProcess == null)
                    throw new Exception(" Process not found. ");


                if (System.IO.File.Exists(DLLPath) == true)
                    InjectGH(TargetProcess, DLLPath);
                else
                    throw new System.IO.FileNotFoundException();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Color.Red);
            }
        }

        private void INJECTION_MODECombo_SelectedIndexChanged(object sender, EventArgs e)
        {
            GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE SelectedMODE = (GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE)INJECTION_MODE_TypeList[INJECTION_MODECombo.SelectedIndex];

            if (SelectedMODE == GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.ManualMap)
            {
                CloakThreadCheck.Checked = false;
                CloakThreadCheck.Enabled = false;
            }
            else
                UnLinkPEBCheck.Enabled = true;

            switch (SelectedMODE)
            {
                case GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.LdrLoadDll:
                {
                        ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrLoadDll is an advanced injection method which uses LdrLoadDll and bypasses LoadLibrary(Ex) hooks.");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.LdrpLoadDll:
                {
                        ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrpLoadDll is an advanced injection method which uses LdrpLoadDll and bypasses LdrLoadDll hooks.");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.LdrpLoadDllInternal:
                {
                        ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrpLoadDllInternal is an experimental injection method which uses LdrpLoadDllInternal.");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.ManualMap:
                {
                        ToolTip1.SetToolTip(INJECTION_MODECombo, "ManualMap is an advanced injection technique which bypasses most module detection methods.");
                        break;
                    }

                default:
                    {
                        ToolTip1.SetToolTip(INJECTION_MODECombo, "LoadLibraryExW is the default injection method which simply uses LoadLibraryExW to load the dll(s).");
                        break;
                    }
            }
        }

        private void LAUNCH_METHODCombo_SelectedIndexChanged(object sender, EventArgs e)
        {
            GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD SelectedMethod = (GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD)LAUNCH_METHOD_TypeList[LAUNCH_METHODCombo.SelectedIndex];

            if (SelectedMethod == GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.NtCreateThreadEx)
                CloakThreadCheck.Enabled = true;
            else
            {
                CloakThreadCheck.Checked = false;
                CloakThreadCheck.Enabled = false;
            }

            switch (SelectedMethod)
            {
                case GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.HijackThread:
                {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "Thread hijacking: Redirects a thread to a codecave to load the dll(s).");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.SetWindowsHookEx:
                {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "SetWindowsHookEx: Adds a hook into the window callback list which then loads the dll(s).");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.KernelCallback:
                {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "KernelCallback: Replaces the __fnCOPYDATA function from the kernel callback table to execute the codecave which then loads the dll(s).");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.QueueUserAPC:
                {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "QueueUserAPC: Registers an asynchronous procedure call to the process' threads which then loads the dll(s).");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD.FakeVEH:
                {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "FakeVEH: Creates and registers a fake VEH which then loads the dll(s) after a page guard exception has been triggered.");
                        break;
                    }

                default:
                    {
                        ToolTip1.SetToolTip(LAUNCH_METHODCombo, "NtCreateThreadEx: Creates a simple remote thread to load the dll(s).");
                        break;
                    }
            }
        }

        private void DLLOptionsCombo_SelectedIndexChanged(object sender, EventArgs e)
        {
            GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx SelectedMethod = (GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx)DLLOptions_TypeList[DLLOptionsCombo.SelectedIndex];

            switch (SelectedMethod)
            {
                case GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx.KEEP_HEADER:
                {
                        ToolTip1.SetToolTip(DLLOptionsCombo, "Keep PEH: Doesn't modify the PE header of the dll(s).");
                        break;
                    }

                case GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx.ERASE_HEADER:
                {
                        ToolTip1.SetToolTip(DLLOptionsCombo, "Erase PEH: Erases the PE header by wrting 0's to it to avoid detections.");
                        break;
                    }

                default:
                    {
                        ToolTip1.SetToolTip(DLLOptionsCombo, "Fake PEH: Replaces the PE header with the PE header of the ntdll.dll.");
                        break;
                    }
            }
        }

        private void WriteLog(string Str, Color BColor)
        {
            this.BeginInvoke(new Action(() =>
            {
                Status.BackColor = BColor;
                Status.Text = Str;
            }));
        }


        #endregion

        #region "Injector"

        private async void InjectGH(Process Proc, string DLLPath)
        {
            WriteLog("Starting injection with the engine: GH_LIB_INJ", Color.BlueViolet);

            await Task.Delay(500); // Or     System.Threading.Thread.Sleep(500)

            GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE SelectedMODE = (GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE)INJECTION_MODE_TypeList[INJECTION_MODECombo.SelectedIndex];
            GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD SelectedMethod = (GH_Inj_Lib_DotNet.Core.GHWrapper.LAUNCH_METHOD)LAUNCH_METHOD_TypeList[LAUNCH_METHODCombo.SelectedIndex];
            GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx DLLOptionsMethod = (GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx)DLLOptions_TypeList[DLLOptionsCombo.SelectedIndex];


            int Flags = 0;

            if (DLLOptionsMethod != GH_Inj_Lib_DotNet.Core.GHWrapper.DLLOptionsEx.KEEP_HEADER)
                Flags += (int)DLLOptionsMethod;

            if (UnLinkPEBCheck.Checked == true)
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.OtherOptions.UNLINK_FROM_PEB;

            if (CloakThreadCheck.Checked == true)
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.OtherOptions.THREAD_CREATE_CLOAKED;

            if (RandomFileNameCheck.Checked == true)
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.OtherOptions.SCRAMBLE_DLL_NAME;

            if (LoadDLLCopyCheck.Checked == true)
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.OtherOptions.LOAD_DLL_COPY;

            if (HijackHandleCheck.Checked == true)
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.OtherOptions.HIJACK_HANDLE;

            if (CloakThreadCheck.Checked == true)
            {

                // Check Enum : Core.GHWrapper.ThreadCreationOptions for more options

                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.ThreadCreationOptions.HIDE_FROM_DEBUGGER;
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.ThreadCreationOptions.FAKE_START_ADDRESS;
            }

            if (SelectedMODE == GH_Inj_Lib_DotNet.Core.GHWrapper.INJECTION_MODE.ManualMap)
            {
                // Check Enum :  Core.GHWrapper.ManualMapping for more options
                Flags += (int)GH_Inj_Lib_DotNet.Core.GHWrapper.ManualMapping.Default;
            }
               

            WriteLog("Injecting " + System.IO.Path.GetFileNameWithoutExtension(DLLPath) + " Mode: " + SelectedMODE.ToString() + " And Method: " + SelectedMethod.ToString(), Color.Cyan);

            await Task.Delay(1000);

            int TimeOUT = int.Parse(NumericUpDown1.Value.ToString()) * 1000;

            GH_Inj_Lib_DotNet.Core.GHWrapper.InjectedEvent InjResult_Thread = new GH_Inj_Lib_DotNet.Core.GHWrapper.InjectedEvent(InjResult);

            GH_Inj_Lib_DotNet.Core.GHWrapper.Inject(InjResult_Thread, (uint)Proc.Id, DLLPath.ToString(), (uint)SelectedMODE, (uint)SelectedMethod, (uint)Flags, (uint)TimeOUT, true);

            await Task.Delay(TimeOUT);
        }

        private void InjResult(string DLL, int Result)
        {
            // This event is activated from the API C ++ therefore any code that writes here will be in another Thread.

            // To return to the thread of your application, simply use Me.BeginInvoke()

            // https://learn.microsoft.com/es-es/dotnet/api/system.windows.forms.control.begininvoke?view=windowsdesktop-7.0

            // That's why I function 'WriteLog' It is continent inside a 'BeginInvoke', if it was not, the application freezes or will not show results.

            string GetResultInfo = GH_Inj_Lib_DotNet.Core.GHWrapper.GetError(Result);

            if (GetResultInfo == "SUCCESS")
                WriteLog(System.IO.Path.GetFileNameWithoutExtension(DLL) + " was injected successfully.", Color.Lime);
            else
                WriteLog(System.IO.Path.GetFileNameWithoutExtension(DLL) + " Errors Occurred While Injecting. CODE: " + Result + " - INFO: " + GetResultInfo, Color.Red);

            if (AutoExitCheck.Checked == true)
            {
                WriteLog("Closing in 4 seconds.", Color.Orange);
                System.Threading.Thread.Sleep(2000);
                Environment.Exit(0);
            }
        }

        #endregion
        
    }
}
