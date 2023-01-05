using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Inj_CSharp_Example
{
    public partial class SymbolsDownloader : Form
    {

        public string EngineDLL { get; set; } = string.Empty;
        public bool Is64 { get; set; } = false;
        private GH_Inj_Lib_DotNet.Core.DynamicInvoke DI = new GH_Inj_Lib_DotNet.Core.DynamicInvoke();

        private bool IsFinalized = false;

        private void SymbolsDownloader_Closing(object sender, CancelEventArgs e)
        {
            if (IsFinalized == false)
            {
                if (MessageBox.Show("Are you sure you want to cancel the download?", "Symbols Downloader", MessageBoxButtons.YesNo) == DialogResult.Yes)
                {
                    DI.Invoke("InterruptDownload", EngineDLL, typeof(bool), null/* TODO Change to default(_) if this is not a reference type */);
                    System.Threading.Thread.Sleep(500);
                    this.DialogResult = DialogResult.Cancel;
                }
                else
                    e.Cancel = true;
            }
        }


        public SymbolsDownloader()
        {
            InitializeComponent();
        }

        private void SymbolsDownloader_Load(object sender, EventArgs e)
        {
           Label1.Text = "Downloading Symbols... ";
        }

        private void SymbolsDownloader_Shown(object sender, EventArgs e)
        {
            DI.Invoke("StartDownload", EngineDLL, typeof(bool), null/* TODO Change to default(_) if this is not a reference type */);
            System.Threading.Thread.Sleep(500);
            Timer1.Enabled = true;
        }

        private void Timer1_Tick(object sender, EventArgs e)
        {
            IntPtr GetSymbolState = (IntPtr)DI.Invoke("GetSymbolState", EngineDLL, typeof(IntPtr), null);
            IntPtr GetImportState = (IntPtr)DI.Invoke("GetImportState", EngineDLL, typeof(IntPtr), null);

            int GetDownloadProgress = GH_Inj_Lib_DotNet.Core.GHWrapper.GetDownloadProgressEx(Is64);
            ProgressBar1.Value = GetDownloadProgress;

            if (GetSymbolState.ToInt32() == 0)
            {
            }

            if (GetImportState.ToInt32() == 0)
            {
                // ImportState Loaded
                IsFinalized = true;
                Timer1.Enabled = false;
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
        }

    }
}
