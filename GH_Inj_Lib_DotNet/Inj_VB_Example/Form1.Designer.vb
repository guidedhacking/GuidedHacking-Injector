<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()>
Partial Class Form1
    Inherits System.Windows.Forms.Form

    'Form overrides dispose to clean up the component list.
    <System.Diagnostics.DebuggerNonUserCode()>
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Required by the Windows Form Designer
    Private components As System.ComponentModel.IContainer

    'NOTE: The following procedure is required by the Windows Form Designer
    'It can be modified using the Windows Form Designer.  
    'Do not modify it using the code editor.
    <System.Diagnostics.DebuggerStepThrough()>
    Private Sub InitializeComponent()
        Me.components = New System.ComponentModel.Container()
        Me.Button1 = New System.Windows.Forms.Button()
        Me.INJECTION_MODECombo = New System.Windows.Forms.ComboBox()
        Me.Label1 = New System.Windows.Forms.Label()
        Me.Label2 = New System.Windows.Forms.Label()
        Me.GroupBox1 = New System.Windows.Forms.GroupBox()
        Me.NumericUpDown1 = New System.Windows.Forms.NumericUpDown()
        Me.AutoExitCheck = New System.Windows.Forms.CheckBox()
        Me.LoadDLLCopyCheck = New System.Windows.Forms.CheckBox()
        Me.RandomFileNameCheck = New System.Windows.Forms.CheckBox()
        Me.UnLinkPEBCheck = New System.Windows.Forms.CheckBox()
        Me.CloakThreadCheck = New System.Windows.Forms.CheckBox()
        Me.HijackHandleCheck = New System.Windows.Forms.CheckBox()
        Me.Label5 = New System.Windows.Forms.Label()
        Me.DLLOptionsCombo = New System.Windows.Forms.ComboBox()
        Me.Label3 = New System.Windows.Forms.Label()
        Me.LAUNCH_METHODCombo = New System.Windows.Forms.ComboBox()
        Me.ProcessList = New System.Windows.Forms.ComboBox()
        Me.Status = New System.Windows.Forms.Label()
        Me.Label6 = New System.Windows.Forms.Label()
        Me.DLL_Path = New System.Windows.Forms.TextBox()
        Me.Button2 = New System.Windows.Forms.Button()
        Me.OpenFileDialog1 = New System.Windows.Forms.OpenFileDialog()
        Me.ToolTip1 = New System.Windows.Forms.ToolTip(Me.components)
        Me.GroupBox1.SuspendLayout()
        CType(Me.NumericUpDown1, System.ComponentModel.ISupportInitialize).BeginInit()
        Me.SuspendLayout()
        '
        'Button1
        '
        Me.Button1.BackColor = System.Drawing.Color.FromArgb(CType(CType(54, Byte), Integer), CType(CType(54, Byte), Integer), CType(CType(54, Byte), Integer))
        Me.Button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat
        Me.Button1.Location = New System.Drawing.Point(15, 304)
        Me.Button1.Name = "Button1"
        Me.Button1.Size = New System.Drawing.Size(362, 47)
        Me.Button1.TabIndex = 0
        Me.Button1.Text = "Inject"
        Me.Button1.UseVisualStyleBackColor = False
        '
        'INJECTION_MODECombo
        '
        Me.INJECTION_MODECombo.BackColor = System.Drawing.Color.White
        Me.INJECTION_MODECombo.FormattingEnabled = True
        Me.INJECTION_MODECombo.Location = New System.Drawing.Point(55, 28)
        Me.INJECTION_MODECombo.Name = "INJECTION_MODECombo"
        Me.INJECTION_MODECombo.Size = New System.Drawing.Size(287, 21)
        Me.INJECTION_MODECombo.TabIndex = 1
        '
        'Label1
        '
        Me.Label1.AutoSize = True
        Me.Label1.Location = New System.Drawing.Point(12, 20)
        Me.Label1.Name = "Label1"
        Me.Label1.Size = New System.Drawing.Size(45, 13)
        Me.Label1.TabIndex = 2
        Me.Label1.Text = "Process"
        '
        'Label2
        '
        Me.Label2.AutoSize = True
        Me.Label2.Location = New System.Drawing.Point(15, 28)
        Me.Label2.Name = "Label2"
        Me.Label2.Size = New System.Drawing.Size(34, 13)
        Me.Label2.TabIndex = 3
        Me.Label2.Text = "Mode"
        '
        'GroupBox1
        '
        Me.GroupBox1.Controls.Add(Me.NumericUpDown1)
        Me.GroupBox1.Controls.Add(Me.AutoExitCheck)
        Me.GroupBox1.Controls.Add(Me.LoadDLLCopyCheck)
        Me.GroupBox1.Controls.Add(Me.RandomFileNameCheck)
        Me.GroupBox1.Controls.Add(Me.UnLinkPEBCheck)
        Me.GroupBox1.Controls.Add(Me.CloakThreadCheck)
        Me.GroupBox1.Controls.Add(Me.HijackHandleCheck)
        Me.GroupBox1.Controls.Add(Me.Label5)
        Me.GroupBox1.Controls.Add(Me.DLLOptionsCombo)
        Me.GroupBox1.Controls.Add(Me.Label3)
        Me.GroupBox1.Controls.Add(Me.LAUNCH_METHODCombo)
        Me.GroupBox1.Controls.Add(Me.Label2)
        Me.GroupBox1.Controls.Add(Me.INJECTION_MODECombo)
        Me.GroupBox1.ForeColor = System.Drawing.Color.White
        Me.GroupBox1.Location = New System.Drawing.Point(15, 100)
        Me.GroupBox1.Name = "GroupBox1"
        Me.GroupBox1.Size = New System.Drawing.Size(362, 198)
        Me.GroupBox1.TabIndex = 4
        Me.GroupBox1.TabStop = False
        Me.GroupBox1.Text = "Injection Options"
        '
        'NumericUpDown1
        '
        Me.NumericUpDown1.Location = New System.Drawing.Point(309, 150)
        Me.NumericUpDown1.Maximum = New Decimal(New Integer() {60, 0, 0, 0})
        Me.NumericUpDown1.Minimum = New Decimal(New Integer() {2, 0, 0, 0})
        Me.NumericUpDown1.Name = "NumericUpDown1"
        Me.NumericUpDown1.Size = New System.Drawing.Size(33, 20)
        Me.NumericUpDown1.TabIndex = 14
        Me.ToolTip1.SetToolTip(Me.NumericUpDown1, "TimeOut (In Seconds)")
        Me.NumericUpDown1.Value = New Decimal(New Integer() {2, 0, 0, 0})
        '
        'AutoExitCheck
        '
        Me.AutoExitCheck.AutoSize = True
        Me.AutoExitCheck.Location = New System.Drawing.Point(235, 156)
        Me.AutoExitCheck.Name = "AutoExitCheck"
        Me.AutoExitCheck.Size = New System.Drawing.Size(68, 17)
        Me.AutoExitCheck.TabIndex = 13
        Me.AutoExitCheck.Text = "Auto Exit"
        Me.AutoExitCheck.UseVisualStyleBackColor = True
        '
        'LoadDLLCopyCheck
        '
        Me.LoadDLLCopyCheck.AutoSize = True
        Me.LoadDLLCopyCheck.Location = New System.Drawing.Point(9, 156)
        Me.LoadDLLCopyCheck.Name = "LoadDLLCopyCheck"
        Me.LoadDLLCopyCheck.Size = New System.Drawing.Size(100, 17)
        Me.LoadDLLCopyCheck.TabIndex = 12
        Me.LoadDLLCopyCheck.Text = "Load DLL Copy"
        Me.LoadDLLCopyCheck.UseVisualStyleBackColor = True
        '
        'RandomFileNameCheck
        '
        Me.RandomFileNameCheck.AutoSize = True
        Me.RandomFileNameCheck.Font = New System.Drawing.Font("Microsoft Sans Serif", 6.75!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.RandomFileNameCheck.Location = New System.Drawing.Point(121, 156)
        Me.RandomFileNameCheck.Name = "RandomFileNameCheck"
        Me.RandomFileNameCheck.Size = New System.Drawing.Size(103, 16)
        Me.RandomFileNameCheck.TabIndex = 11
        Me.RandomFileNameCheck.Text = "Random File Name"
        Me.RandomFileNameCheck.UseVisualStyleBackColor = True
        '
        'UnLinkPEBCheck
        '
        Me.UnLinkPEBCheck.AutoSize = True
        Me.UnLinkPEBCheck.Location = New System.Drawing.Point(235, 121)
        Me.UnLinkPEBCheck.Name = "UnLinkPEBCheck"
        Me.UnLinkPEBCheck.Size = New System.Drawing.Size(107, 17)
        Me.UnLinkPEBCheck.TabIndex = 10
        Me.UnLinkPEBCheck.Text = "UnLink from PEB"
        Me.UnLinkPEBCheck.UseVisualStyleBackColor = True
        '
        'CloakThreadCheck
        '
        Me.CloakThreadCheck.AutoSize = True
        Me.CloakThreadCheck.Location = New System.Drawing.Point(121, 121)
        Me.CloakThreadCheck.Name = "CloakThreadCheck"
        Me.CloakThreadCheck.Size = New System.Drawing.Size(90, 17)
        Me.CloakThreadCheck.TabIndex = 9
        Me.CloakThreadCheck.Text = "Cloak Thread"
        Me.CloakThreadCheck.UseVisualStyleBackColor = True
        '
        'HijackHandleCheck
        '
        Me.HijackHandleCheck.AutoSize = True
        Me.HijackHandleCheck.Location = New System.Drawing.Point(9, 121)
        Me.HijackHandleCheck.Name = "HijackHandleCheck"
        Me.HijackHandleCheck.Size = New System.Drawing.Size(93, 17)
        Me.HijackHandleCheck.TabIndex = 8
        Me.HijackHandleCheck.Text = "Hijack Handle"
        Me.HijackHandleCheck.UseVisualStyleBackColor = True
        '
        'Label5
        '
        Me.Label5.AutoSize = True
        Me.Label5.Location = New System.Drawing.Point(6, 82)
        Me.Label5.Name = "Label5"
        Me.Label5.Size = New System.Drawing.Size(66, 13)
        Me.Label5.TabIndex = 7
        Me.Label5.Text = "DLL Options"
        '
        'DLLOptionsCombo
        '
        Me.DLLOptionsCombo.BackColor = System.Drawing.Color.White
        Me.DLLOptionsCombo.FormattingEnabled = True
        Me.DLLOptionsCombo.Location = New System.Drawing.Point(78, 82)
        Me.DLLOptionsCombo.Name = "DLLOptionsCombo"
        Me.DLLOptionsCombo.Size = New System.Drawing.Size(264, 21)
        Me.DLLOptionsCombo.TabIndex = 6
        '
        'Label3
        '
        Me.Label3.AutoSize = True
        Me.Label3.Location = New System.Drawing.Point(6, 55)
        Me.Label3.Name = "Label3"
        Me.Label3.Size = New System.Drawing.Size(43, 13)
        Me.Label3.TabIndex = 5
        Me.Label3.Text = "Method"
        '
        'LAUNCH_METHODCombo
        '
        Me.LAUNCH_METHODCombo.BackColor = System.Drawing.Color.White
        Me.LAUNCH_METHODCombo.FormattingEnabled = True
        Me.LAUNCH_METHODCombo.Location = New System.Drawing.Point(55, 55)
        Me.LAUNCH_METHODCombo.Name = "LAUNCH_METHODCombo"
        Me.LAUNCH_METHODCombo.Size = New System.Drawing.Size(287, 21)
        Me.LAUNCH_METHODCombo.TabIndex = 4
        '
        'ProcessList
        '
        Me.ProcessList.BackColor = System.Drawing.Color.White
        Me.ProcessList.FormattingEnabled = True
        Me.ProcessList.Location = New System.Drawing.Point(63, 20)
        Me.ProcessList.Name = "ProcessList"
        Me.ProcessList.Size = New System.Drawing.Size(313, 21)
        Me.ProcessList.TabIndex = 5
        '
        'Status
        '
        Me.Status.Dock = System.Windows.Forms.DockStyle.Bottom
        Me.Status.Location = New System.Drawing.Point(0, 356)
        Me.Status.Name = "Status"
        Me.Status.Size = New System.Drawing.Size(391, 23)
        Me.Status.TabIndex = 6
        Me.Status.Text = "Select Process..."
        Me.Status.TextAlign = System.Drawing.ContentAlignment.MiddleLeft
        '
        'Label6
        '
        Me.Label6.AutoSize = True
        Me.Label6.Location = New System.Drawing.Point(12, 61)
        Me.Label6.Name = "Label6"
        Me.Label6.Size = New System.Drawing.Size(52, 13)
        Me.Label6.TabIndex = 7
        Me.Label6.Text = "DLL Path"
        '
        'DLL_Path
        '
        Me.DLL_Path.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
        Me.DLL_Path.Location = New System.Drawing.Point(63, 59)
        Me.DLL_Path.Name = "DLL_Path"
        Me.DLL_Path.ReadOnly = True
        Me.DLL_Path.Size = New System.Drawing.Size(255, 20)
        Me.DLL_Path.TabIndex = 8
        '
        'Button2
        '
        Me.Button2.BackColor = System.Drawing.Color.FromArgb(CType(CType(54, Byte), Integer), CType(CType(54, Byte), Integer), CType(CType(54, Byte), Integer))
        Me.Button2.FlatStyle = System.Windows.Forms.FlatStyle.Flat
        Me.Button2.Location = New System.Drawing.Point(326, 52)
        Me.Button2.Name = "Button2"
        Me.Button2.Size = New System.Drawing.Size(50, 31)
        Me.Button2.TabIndex = 9
        Me.Button2.Text = "Select"
        Me.Button2.UseVisualStyleBackColor = False
        '
        'OpenFileDialog1
        '
        Me.OpenFileDialog1.Filter = "DLL files (*.dll)|*.dll"
        Me.OpenFileDialog1.Tag = "Select File"
        '
        'Form1
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(6.0!, 13.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink
        Me.BackColor = System.Drawing.Color.FromArgb(CType(CType(24, Byte), Integer), CType(CType(24, Byte), Integer), CType(CType(24, Byte), Integer))
        Me.ClientSize = New System.Drawing.Size(391, 379)
        Me.Controls.Add(Me.DLL_Path)
        Me.Controls.Add(Me.Button2)
        Me.Controls.Add(Me.Label6)
        Me.Controls.Add(Me.Status)
        Me.Controls.Add(Me.ProcessList)
        Me.Controls.Add(Me.GroupBox1)
        Me.Controls.Add(Me.Label1)
        Me.Controls.Add(Me.Button1)
        Me.ForeColor = System.Drawing.Color.White
        Me.MaximizeBox = False
        Me.Name = "Form1"
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "GH Injector DotNet Example"
        Me.TopMost = True
        Me.GroupBox1.ResumeLayout(False)
        Me.GroupBox1.PerformLayout()
        CType(Me.NumericUpDown1, System.ComponentModel.ISupportInitialize).EndInit()
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub

    Friend WithEvents Button1 As Button
    Friend WithEvents INJECTION_MODECombo As ComboBox
    Friend WithEvents Label1 As Label
    Friend WithEvents Label2 As Label
    Friend WithEvents GroupBox1 As GroupBox
    Friend WithEvents Label3 As Label
    Friend WithEvents LAUNCH_METHODCombo As ComboBox
    Friend WithEvents ProcessList As ComboBox
    Friend WithEvents Status As Label
    Friend WithEvents Label5 As Label
    Friend WithEvents DLLOptionsCombo As ComboBox
    Friend WithEvents AutoExitCheck As CheckBox
    Friend WithEvents LoadDLLCopyCheck As CheckBox
    Friend WithEvents RandomFileNameCheck As CheckBox
    Friend WithEvents UnLinkPEBCheck As CheckBox
    Friend WithEvents CloakThreadCheck As CheckBox
    Friend WithEvents HijackHandleCheck As CheckBox
    Friend WithEvents Label6 As Label
    Friend WithEvents DLL_Path As TextBox
    Friend WithEvents Button2 As Button
    Friend WithEvents OpenFileDialog1 As OpenFileDialog
    Friend WithEvents ToolTip1 As ToolTip
    Friend WithEvents NumericUpDown1 As NumericUpDown
End Class
