namespace Inj_CSharp_Example
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.ToolTip1 = new System.Windows.Forms.ToolTip(this.components);
            this.NumericUpDown1 = new System.Windows.Forms.NumericUpDown();
            this.DLL_Path = new System.Windows.Forms.TextBox();
            this.Button2 = new System.Windows.Forms.Button();
            this.Label6 = new System.Windows.Forms.Label();
            this.Status = new System.Windows.Forms.Label();
            this.AutoExitCheck = new System.Windows.Forms.CheckBox();
            this.LoadDLLCopyCheck = new System.Windows.Forms.CheckBox();
            this.RandomFileNameCheck = new System.Windows.Forms.CheckBox();
            this.UnLinkPEBCheck = new System.Windows.Forms.CheckBox();
            this.CloakThreadCheck = new System.Windows.Forms.CheckBox();
            this.ProcessList = new System.Windows.Forms.ComboBox();
            this.HijackHandleCheck = new System.Windows.Forms.CheckBox();
            this.DLLOptionsCombo = new System.Windows.Forms.ComboBox();
            this.Label3 = new System.Windows.Forms.Label();
            this.LAUNCH_METHODCombo = new System.Windows.Forms.ComboBox();
            this.OpenFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.GroupBox1 = new System.Windows.Forms.GroupBox();
            this.Label5 = new System.Windows.Forms.Label();
            this.Label2 = new System.Windows.Forms.Label();
            this.INJECTION_MODECombo = new System.Windows.Forms.ComboBox();
            this.Label1 = new System.Windows.Forms.Label();
            this.Button1 = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.NumericUpDown1)).BeginInit();
            this.GroupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // NumericUpDown1
            // 
            this.NumericUpDown1.Location = new System.Drawing.Point(309, 150);
            this.NumericUpDown1.Maximum = new decimal(new int[] {
            60,
            0,
            0,
            0});
            this.NumericUpDown1.Minimum = new decimal(new int[] {
            2,
            0,
            0,
            0});
            this.NumericUpDown1.Name = "NumericUpDown1";
            this.NumericUpDown1.Size = new System.Drawing.Size(33, 20);
            this.NumericUpDown1.TabIndex = 14;
            this.ToolTip1.SetToolTip(this.NumericUpDown1, "TimeOut (In Seconds)");
            this.NumericUpDown1.Value = new decimal(new int[] {
            2,
            0,
            0,
            0});
            // 
            // DLL_Path
            // 
            this.DLL_Path.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.DLL_Path.Location = new System.Drawing.Point(63, 49);
            this.DLL_Path.Name = "DLL_Path";
            this.DLL_Path.ReadOnly = true;
            this.DLL_Path.Size = new System.Drawing.Size(255, 20);
            this.DLL_Path.TabIndex = 16;
            // 
            // Button2
            // 
            this.Button2.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(54)))), ((int)(((byte)(54)))), ((int)(((byte)(54)))));
            this.Button2.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.Button2.Location = new System.Drawing.Point(326, 42);
            this.Button2.Name = "Button2";
            this.Button2.Size = new System.Drawing.Size(50, 31);
            this.Button2.TabIndex = 17;
            this.Button2.Text = "Select";
            this.Button2.UseVisualStyleBackColor = false;
            this.Button2.Click += new System.EventHandler(this.Button2_Click);
            // 
            // Label6
            // 
            this.Label6.AutoSize = true;
            this.Label6.Location = new System.Drawing.Point(12, 51);
            this.Label6.Name = "Label6";
            this.Label6.Size = new System.Drawing.Size(52, 13);
            this.Label6.TabIndex = 15;
            this.Label6.Text = "DLL Path";
            // 
            // Status
            // 
            this.Status.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.Status.Location = new System.Drawing.Point(0, 356);
            this.Status.Name = "Status";
            this.Status.Size = new System.Drawing.Size(391, 23);
            this.Status.TabIndex = 14;
            this.Status.Text = "Select Process...";
            this.Status.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // AutoExitCheck
            // 
            this.AutoExitCheck.AutoSize = true;
            this.AutoExitCheck.Location = new System.Drawing.Point(235, 156);
            this.AutoExitCheck.Name = "AutoExitCheck";
            this.AutoExitCheck.Size = new System.Drawing.Size(68, 17);
            this.AutoExitCheck.TabIndex = 13;
            this.AutoExitCheck.Text = "Auto Exit";
            this.AutoExitCheck.UseVisualStyleBackColor = true;
            // 
            // LoadDLLCopyCheck
            // 
            this.LoadDLLCopyCheck.AutoSize = true;
            this.LoadDLLCopyCheck.Location = new System.Drawing.Point(9, 156);
            this.LoadDLLCopyCheck.Name = "LoadDLLCopyCheck";
            this.LoadDLLCopyCheck.Size = new System.Drawing.Size(100, 17);
            this.LoadDLLCopyCheck.TabIndex = 12;
            this.LoadDLLCopyCheck.Text = "Load DLL Copy";
            this.LoadDLLCopyCheck.UseVisualStyleBackColor = true;
            // 
            // RandomFileNameCheck
            // 
            this.RandomFileNameCheck.AutoSize = true;
            this.RandomFileNameCheck.Font = new System.Drawing.Font("Microsoft Sans Serif", 6.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.RandomFileNameCheck.Location = new System.Drawing.Point(121, 156);
            this.RandomFileNameCheck.Name = "RandomFileNameCheck";
            this.RandomFileNameCheck.Size = new System.Drawing.Size(103, 16);
            this.RandomFileNameCheck.TabIndex = 11;
            this.RandomFileNameCheck.Text = "Random File Name";
            this.RandomFileNameCheck.UseVisualStyleBackColor = true;
            // 
            // UnLinkPEBCheck
            // 
            this.UnLinkPEBCheck.AutoSize = true;
            this.UnLinkPEBCheck.Location = new System.Drawing.Point(235, 121);
            this.UnLinkPEBCheck.Name = "UnLinkPEBCheck";
            this.UnLinkPEBCheck.Size = new System.Drawing.Size(107, 17);
            this.UnLinkPEBCheck.TabIndex = 10;
            this.UnLinkPEBCheck.Text = "UnLink from PEB";
            this.UnLinkPEBCheck.UseVisualStyleBackColor = true;
            // 
            // CloakThreadCheck
            // 
            this.CloakThreadCheck.AutoSize = true;
            this.CloakThreadCheck.Location = new System.Drawing.Point(121, 121);
            this.CloakThreadCheck.Name = "CloakThreadCheck";
            this.CloakThreadCheck.Size = new System.Drawing.Size(90, 17);
            this.CloakThreadCheck.TabIndex = 9;
            this.CloakThreadCheck.Text = "Cloak Thread";
            this.CloakThreadCheck.UseVisualStyleBackColor = true;
            // 
            // ProcessList
            // 
            this.ProcessList.BackColor = System.Drawing.Color.White;
            this.ProcessList.FormattingEnabled = true;
            this.ProcessList.Location = new System.Drawing.Point(63, 10);
            this.ProcessList.Name = "ProcessList";
            this.ProcessList.Size = new System.Drawing.Size(313, 21);
            this.ProcessList.TabIndex = 13;
            this.ProcessList.Click += new System.EventHandler(this.ProcessList_Click);
            // 
            // HijackHandleCheck
            // 
            this.HijackHandleCheck.AutoSize = true;
            this.HijackHandleCheck.Location = new System.Drawing.Point(9, 121);
            this.HijackHandleCheck.Name = "HijackHandleCheck";
            this.HijackHandleCheck.Size = new System.Drawing.Size(93, 17);
            this.HijackHandleCheck.TabIndex = 8;
            this.HijackHandleCheck.Text = "Hijack Handle";
            this.HijackHandleCheck.UseVisualStyleBackColor = true;
            // 
            // DLLOptionsCombo
            // 
            this.DLLOptionsCombo.BackColor = System.Drawing.Color.White;
            this.DLLOptionsCombo.FormattingEnabled = true;
            this.DLLOptionsCombo.Location = new System.Drawing.Point(78, 82);
            this.DLLOptionsCombo.Name = "DLLOptionsCombo";
            this.DLLOptionsCombo.Size = new System.Drawing.Size(264, 21);
            this.DLLOptionsCombo.TabIndex = 6;
            this.DLLOptionsCombo.Click += new System.EventHandler(this.DLLOptionsCombo_SelectedIndexChanged);
            // 
            // Label3
            // 
            this.Label3.AutoSize = true;
            this.Label3.Location = new System.Drawing.Point(6, 55);
            this.Label3.Name = "Label3";
            this.Label3.Size = new System.Drawing.Size(43, 13);
            this.Label3.TabIndex = 5;
            this.Label3.Text = "Method";
            // 
            // LAUNCH_METHODCombo
            // 
            this.LAUNCH_METHODCombo.BackColor = System.Drawing.Color.White;
            this.LAUNCH_METHODCombo.FormattingEnabled = true;
            this.LAUNCH_METHODCombo.Location = new System.Drawing.Point(55, 55);
            this.LAUNCH_METHODCombo.Name = "LAUNCH_METHODCombo";
            this.LAUNCH_METHODCombo.Size = new System.Drawing.Size(287, 21);
            this.LAUNCH_METHODCombo.TabIndex = 4;
            this.LAUNCH_METHODCombo.Click += new System.EventHandler(this.LAUNCH_METHODCombo_SelectedIndexChanged);
            // 
            // OpenFileDialog1
            // 
            this.OpenFileDialog1.Filter = "DLL files (*.dll)|*.dll";
            this.OpenFileDialog1.Tag = "Select File";
            // 
            // GroupBox1
            // 
            this.GroupBox1.Controls.Add(this.NumericUpDown1);
            this.GroupBox1.Controls.Add(this.AutoExitCheck);
            this.GroupBox1.Controls.Add(this.LoadDLLCopyCheck);
            this.GroupBox1.Controls.Add(this.RandomFileNameCheck);
            this.GroupBox1.Controls.Add(this.UnLinkPEBCheck);
            this.GroupBox1.Controls.Add(this.CloakThreadCheck);
            this.GroupBox1.Controls.Add(this.HijackHandleCheck);
            this.GroupBox1.Controls.Add(this.Label5);
            this.GroupBox1.Controls.Add(this.DLLOptionsCombo);
            this.GroupBox1.Controls.Add(this.Label3);
            this.GroupBox1.Controls.Add(this.LAUNCH_METHODCombo);
            this.GroupBox1.Controls.Add(this.Label2);
            this.GroupBox1.Controls.Add(this.INJECTION_MODECombo);
            this.GroupBox1.ForeColor = System.Drawing.Color.White;
            this.GroupBox1.Location = new System.Drawing.Point(15, 90);
            this.GroupBox1.Name = "GroupBox1";
            this.GroupBox1.Size = new System.Drawing.Size(362, 198);
            this.GroupBox1.TabIndex = 12;
            this.GroupBox1.TabStop = false;
            this.GroupBox1.Text = "Injection Options";
            // 
            // Label5
            // 
            this.Label5.AutoSize = true;
            this.Label5.Location = new System.Drawing.Point(6, 82);
            this.Label5.Name = "Label5";
            this.Label5.Size = new System.Drawing.Size(66, 13);
            this.Label5.TabIndex = 7;
            this.Label5.Text = "DLL Options";
            // 
            // Label2
            // 
            this.Label2.AutoSize = true;
            this.Label2.Location = new System.Drawing.Point(15, 28);
            this.Label2.Name = "Label2";
            this.Label2.Size = new System.Drawing.Size(34, 13);
            this.Label2.TabIndex = 3;
            this.Label2.Text = "Mode";
            // 
            // INJECTION_MODECombo
            // 
            this.INJECTION_MODECombo.BackColor = System.Drawing.Color.White;
            this.INJECTION_MODECombo.FormattingEnabled = true;
            this.INJECTION_MODECombo.Location = new System.Drawing.Point(55, 28);
            this.INJECTION_MODECombo.Name = "INJECTION_MODECombo";
            this.INJECTION_MODECombo.Size = new System.Drawing.Size(287, 21);
            this.INJECTION_MODECombo.TabIndex = 1;
            this.INJECTION_MODECombo.Click += new System.EventHandler(this.INJECTION_MODECombo_SelectedIndexChanged);
            // 
            // Label1
            // 
            this.Label1.AutoSize = true;
            this.Label1.Location = new System.Drawing.Point(12, 10);
            this.Label1.Name = "Label1";
            this.Label1.Size = new System.Drawing.Size(45, 13);
            this.Label1.TabIndex = 11;
            this.Label1.Text = "Process";
            // 
            // Button1
            // 
            this.Button1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(54)))), ((int)(((byte)(54)))), ((int)(((byte)(54)))));
            this.Button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.Button1.Location = new System.Drawing.Point(15, 294);
            this.Button1.Name = "Button1";
            this.Button1.Size = new System.Drawing.Size(362, 47);
            this.Button1.TabIndex = 10;
            this.Button1.Text = "Inject";
            this.Button1.UseVisualStyleBackColor = false;
            this.Button1.Click += new System.EventHandler(this.Button1_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(24)))), ((int)(((byte)(24)))), ((int)(((byte)(24)))));
            this.ClientSize = new System.Drawing.Size(391, 379);
            this.Controls.Add(this.DLL_Path);
            this.Controls.Add(this.Button2);
            this.Controls.Add(this.Label6);
            this.Controls.Add(this.Status);
            this.Controls.Add(this.ProcessList);
            this.Controls.Add(this.GroupBox1);
            this.Controls.Add(this.Label1);
            this.Controls.Add(this.Button1);
            this.ForeColor = System.Drawing.Color.White;
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "GH Injector DotNet Example";
            this.TopMost = true;
            this.Load += new System.EventHandler(this.Form1_Load);
            this.Shown += new System.EventHandler(this.Form1_Shown);
            ((System.ComponentModel.ISupportInitialize)(this.NumericUpDown1)).EndInit();
            this.GroupBox1.ResumeLayout(false);
            this.GroupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        internal System.Windows.Forms.ToolTip ToolTip1;
        internal System.Windows.Forms.NumericUpDown NumericUpDown1;
        internal System.Windows.Forms.TextBox DLL_Path;
        internal System.Windows.Forms.Button Button2;
        internal System.Windows.Forms.Label Label6;
        internal System.Windows.Forms.Label Status;
        internal System.Windows.Forms.CheckBox AutoExitCheck;
        internal System.Windows.Forms.CheckBox LoadDLLCopyCheck;
        internal System.Windows.Forms.CheckBox RandomFileNameCheck;
        internal System.Windows.Forms.CheckBox UnLinkPEBCheck;
        internal System.Windows.Forms.CheckBox CloakThreadCheck;
        internal System.Windows.Forms.ComboBox ProcessList;
        internal System.Windows.Forms.CheckBox HijackHandleCheck;
        internal System.Windows.Forms.ComboBox DLLOptionsCombo;
        internal System.Windows.Forms.Label Label3;
        internal System.Windows.Forms.ComboBox LAUNCH_METHODCombo;
        internal System.Windows.Forms.OpenFileDialog OpenFileDialog1;
        internal System.Windows.Forms.GroupBox GroupBox1;
        internal System.Windows.Forms.Label Label5;
        internal System.Windows.Forms.Label Label2;
        internal System.Windows.Forms.ComboBox INJECTION_MODECombo;
        internal System.Windows.Forms.Label Label1;
        internal System.Windows.Forms.Button Button1;
    }
}

