Imports System.Runtime.InteropServices
Imports GH_Inj_Lib_DotNet

Public Class Form1


#Region " Pinvoke "

    <DllImport("kernel32.dll", SetLastError:=True, CharSet:=CharSet.Ansi)>
    Public Shared Function LoadLibrary(ByVal lpFileName As String) As IntPtr
    End Function

#End Region

#Region " Declare "

    Public Is64OS As Boolean = Environment.Is64BitOperatingSystem

    Private INJECTION_MODE_TypeList As List(Of Object) = [Enum].GetValues(GetType(Core.GHWrapper.INJECTION_MODE)).Cast(Of Object)().ToList()
    Private LAUNCH_METHOD_TypeList As List(Of Object) = [Enum].GetValues(GetType(Core.GHWrapper.LAUNCH_METHOD)).Cast(Of Object)().ToList()
    Private DLLOptions_TypeList As List(Of Object) = [Enum].GetValues(GetType(Core.GHWrapper.DLLOptionsEx)).Cast(Of Object)().ToList()
    Private ManualMapOptions_TypeList As List(Of Object) = [Enum].GetValues(GetType(Core.GHWrapper.ManualMapping)).Cast(Of Object)().ToList()
    Private CloakOptions_TypeList As List(Of Object) = [Enum].GetValues(GetType(Core.GHWrapper.ThreadCreationOptions)).Cast(Of Object)().ToList()

#End Region


    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        StartRuntimes()
    End Sub

    Private Sub Form1_Shown(sender As Object, e As EventArgs) Handles Me.Shown
        InitializeEngines()
    End Sub

    Private Sub InitializeEngines()

        Dim ArqHelper As Core.HelperExtractor.Arq = Core.HelperExtractor.Arq.x86

        ' This will change it depending on your needs.
        ' If your Then compilation Is X86, you must place X86 And vice versa.

        '  In the event that your compilation Is Any CPU, you must uncheck 'prefer 32 bits' if it is for x64 and vice versa.

        '''''''''''''''''''''''''''
        'Extracting Wrapper
        '''''''''''''''''''''''''''

        Try
            Core.HelperExtractor.Extract(ArqHelper)
        Catch ex As Exception
            MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK)
            Environment.Exit(0)
        End Try

        '''''''''''''''''''''''''''
        'Load Wrapper
        '''''''''''''''''''''''''''

        Dim InjHelperLoadResult As IntPtr = LoadLibrary(Core.GHWrapper.API)

        If InjHelperLoadResult = IntPtr.Zero Then
            'This usually happens because it is trying to load core.helperextractor.arq.x64 in a 32bits system.
            MessageBox.Show("The Wrapper could not be loaded, check if the coinside destination architecture.", "Error", MessageBoxButtons.OK)
            Environment.Exit(0)
        End If

        '''''''''''''''''''''''''''
        'Load GH Injection Library
        '''''''''''''''''''''''''''

        Dim EngineDLL As String = String.Empty

        Select Case ArqHelper
            Case Core.HelperExtractor.Arq.x86
                EngineDLL = "GH Injector - x86.dll"
            Case Core.HelperExtractor.Arq.x64
                EngineDLL = "GH Injector - x64.dll"
        End Select

        Dim LoadResult As IntPtr = LoadLibrary(EngineDLL)

        If LoadResult = IntPtr.Zero Then
            'This usually happens because it is trying to load core.helperextractor.arq.x64 in a 32bits system.
            MessageBox.Show("Failed to load : " & EngineDLL, "Error", MessageBoxButtons.OK)
            Environment.Exit(0)
        End If

        Core.GHWrapper.SetManualHook(EngineDLL)


        '''''''''''''''''''''''''''
        'Load Symbols
        '''''''''''''''''''''''''''

        If IO.Directory.Exists("x86") = False Then IO.Directory.CreateDirectory("x86")
        If IO.Directory.Exists("x64") = False Then IO.Directory.CreateDirectory("x64")

        Dim ShowDialog As Boolean = False

        If ArqHelper = Core.HelperExtractor.Arq.x86 Then
            If System.IO.File.Exists(IO.Path.Combine("x86", "wntdll.pdb")) = False Then
                ShowDialog = True
            End If
        Else
            If System.IO.File.Exists(IO.Path.Combine("x64", "ntdll.pdb")) = False Then
                ShowDialog = True
            End If
        End If

        If ShowDialog = True Then

            Dim SymbolDownloader As SymbolsDownloader = New SymbolsDownloader With {.EngineDLL = EngineDLL, .Is64 = (ArqHelper = Core.HelperExtractor.Arq.x64)}

            If Not SymbolDownloader.ShowDialog = DialogResult.OK Then
                MessageBox.Show("He has canceled the download process, you must download the symbols to work.", "Error", MessageBoxButtons.OK)
                Environment.Exit(0)
            End If

        End If

    End Sub

#Region " UI "

    Public Sub StartRuntimes()

        INJECTION_MODECombo.Items.AddRange(INJECTION_MODE_TypeList.ToArray)
        INJECTION_MODECombo.SelectedIndex = 0

        LAUNCH_METHODCombo.Items.AddRange(LAUNCH_METHOD_TypeList.ToArray)
        LAUNCH_METHODCombo.SelectedIndex = 0

        DLLOptionsCombo.Items.AddRange(DLLOptions_TypeList.ToArray)
        DLLOptionsCombo.SelectedIndex = 0

    End Sub

    Private Sub ProcessList_Click(sender As Object, e As EventArgs) Handles ProcessList.Click
        ListProcess()
    End Sub

    Public Sub ListProcess()
        ProcessList.Items.Clear()
        Dim ProcShowFormat As New List(Of String)
        Dim ProcList As List(Of Process) = Process.GetProcesses.ToList

        For Each Proc As Process In ProcList
            ProcShowFormat.Add(String.Format("{0} ({1})", Proc.ProcessName, Proc.Id))
        Next

        ProcessList.Items.AddRange(ProcShowFormat.ToArray)
    End Sub

    Private Sub Button2_Click(sender As Object, e As EventArgs) Handles Button2.Click
        If OpenFileDialog1.ShowDialog = DialogResult.OK Then
            DLL_Path.Text = OpenFileDialog1.FileName
        End If
    End Sub

    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        Try
            Dim CurrentSelected As String = ProcessList.Text
            If CurrentSelected = String.Empty Then Throw New Exception(" Select Process ! ")

            Dim startIndex As Integer = CurrentSelected.IndexOf("(") + 1
            Dim length As Integer = CurrentSelected.IndexOf(")") - startIndex
            Dim ProcessID As String = CurrentSelected.Substring(startIndex, length)
            Dim DLLPath As String = DLL_Path.Text

            Dim TargetProcess As Process = Process.GetProcessById(ProcessID)

            If TargetProcess Is Nothing Then Throw New Exception(" Process not found. ")


            If IO.File.Exists(DLLPath) = True Then

                InjectGH(TargetProcess, DLLPath)

            Else
                Throw New IO.FileNotFoundException
            End If

        Catch ex As Exception
            WriteLog(ex.Message, Color.Red)
        End Try
    End Sub

    Private Sub INJECTION_MODECombo_SelectedIndexChanged(sender As Object, e As EventArgs) Handles INJECTION_MODECombo.SelectedIndexChanged

        Dim SelectedMODE As Core.GHWrapper.INJECTION_MODE = INJECTION_MODE_TypeList(INJECTION_MODECombo.SelectedIndex)

        If SelectedMODE = Core.GHWrapper.INJECTION_MODE.ManualMap Then
            CloakThreadCheck.Checked = False
            CloakThreadCheck.Enabled = False
            ' ManualMapOptions1.Visible = True
        Else
            UnLinkPEBCheck.Enabled = True
            ' ManualMapOptions1.Visible = False
        End If

        Select Case SelectedMODE
            Case Core.GHWrapper.INJECTION_MODE.LdrLoadDll
                ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrLoadDll is an advanced injection method which uses LdrLoadDll and bypasses LoadLibrary(Ex) hooks.")
            Case Core.GHWrapper.INJECTION_MODE.LdrpLoadDll
                ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrpLoadDll is an advanced injection method which uses LdrpLoadDll and bypasses LdrLoadDll hooks.")
            Case Core.GHWrapper.INJECTION_MODE.LdrpLoadDllInternal
                ToolTip1.SetToolTip(INJECTION_MODECombo, "LdrpLoadDllInternal is an experimental injection method which uses LdrpLoadDllInternal.")
            Case Core.GHWrapper.INJECTION_MODE.ManualMap
                ToolTip1.SetToolTip(INJECTION_MODECombo, "ManualMap is an advanced injection technique which bypasses most module detection methods.")
            Case Else
                ToolTip1.SetToolTip(INJECTION_MODECombo, "LoadLibraryExW is the default injection method which simply uses LoadLibraryExW to load the dll(s).")
        End Select

    End Sub

    Private Sub LAUNCH_METHODCombo_SelectedIndexChanged(sender As Object, e As EventArgs) Handles LAUNCH_METHODCombo.SelectedIndexChanged
        Dim SelectedMethod As Core.GHWrapper.LAUNCH_METHOD = LAUNCH_METHOD_TypeList(LAUNCH_METHODCombo.SelectedIndex)

        If SelectedMethod = Core.GHWrapper.LAUNCH_METHOD.NtCreateThreadEx Then
            CloakThreadCheck.Enabled = True
        Else
            CloakThreadCheck.Checked = False
            CloakThreadCheck.Enabled = False
        End If

        Select Case SelectedMethod
            Case Core.GHWrapper.LAUNCH_METHOD.HijackThread
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "Thread hijacking: Redirects a thread to a codecave to load the dll(s).")
            Case Core.GHWrapper.LAUNCH_METHOD.SetWindowsHookEx
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "SetWindowsHookEx: Adds a hook into the window callback list which then loads the dll(s).")
            Case Core.GHWrapper.LAUNCH_METHOD.KernelCallback
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "KernelCallback: Replaces the __fnCOPYDATA function from the kernel callback table to execute the codecave which then loads the dll(s).")
            Case Core.GHWrapper.LAUNCH_METHOD.QueueUserAPC
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "QueueUserAPC: Registers an asynchronous procedure call to the process' threads which then loads the dll(s).")
            Case Core.GHWrapper.LAUNCH_METHOD.FakeVEH
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "FakeVEH: Creates and registers a fake VEH which then loads the dll(s) after a page guard exception has been triggered.")
            Case Else
                ToolTip1.SetToolTip(LAUNCH_METHODCombo, "NtCreateThreadEx: Creates a simple remote thread to load the dll(s).")
        End Select
    End Sub

    Private Sub DLLOptionsCombo_SelectedIndexChanged(sender As Object, e As EventArgs) Handles DLLOptionsCombo.SelectedIndexChanged
        Dim SelectedMethod As Core.GHWrapper.DLLOptionsEx = DLLOptions_TypeList(DLLOptionsCombo.SelectedIndex)

        Select Case SelectedMethod
            Case Core.GHWrapper.DLLOptionsEx.KEEP_HEADER
                ToolTip1.SetToolTip(DLLOptionsCombo, "Keep PEH: Doesn't modify the PE header of the dll(s).")
            Case Core.GHWrapper.DLLOptionsEx.ERASE_HEADER
                ToolTip1.SetToolTip(DLLOptionsCombo, "Erase PEH: Erases the PE header by wrting 0's to it to avoid detections.")
            Case Else
                ToolTip1.SetToolTip(DLLOptionsCombo, "Fake PEH: Replaces the PE header with the PE header of the ntdll.dll.")
        End Select
    End Sub

    Private Sub WriteLog(ByVal Str As String, ByVal BColor As Color)
        Me.BeginInvoke(Sub()
                           Status.BackColor = BColor
                           Status.Text = Str
                       End Sub)

    End Sub

#End Region

#Region " Injector "

    Private Async Sub InjectGH(ByVal Proc As Process, ByVal DLLPath As String)
        WriteLog("Starting injection with the engine: GH_LIB_INJ", Color.BlueViolet)

        Await Task.Delay(500) ' Or     System.Threading.Thread.Sleep(500)

        Dim SelectedMODE As Core.GHWrapper.INJECTION_MODE = INJECTION_MODE_TypeList(INJECTION_MODECombo.SelectedIndex)
        Dim SelectedMethod As Core.GHWrapper.LAUNCH_METHOD = LAUNCH_METHOD_TypeList(LAUNCH_METHODCombo.SelectedIndex)
        Dim DLLOptionsMethod As Core.GHWrapper.DLLOptionsEx = DLLOptions_TypeList(DLLOptionsCombo.SelectedIndex)


        Dim Flags As Integer = 0

        If Not DLLOptionsMethod = Core.GHWrapper.DLLOptionsEx.KEEP_HEADER Then
            Flags += DLLOptionsMethod
        End If

        If UnLinkPEBCheck.Checked = True Then Flags += Core.GHWrapper.OtherOptions.UNLINK_FROM_PEB

        If CloakThreadCheck.Checked = True Then Flags += Core.GHWrapper.OtherOptions.THREAD_CREATE_CLOAKED

        If RandomFileNameCheck.Checked = True Then Flags += Core.GHWrapper.OtherOptions.SCRAMBLE_DLL_NAME

        If LoadDLLCopyCheck.Checked = True Then Flags += Core.GHWrapper.OtherOptions.LOAD_DLL_COPY

        If HijackHandleCheck.Checked = True Then Flags += Core.GHWrapper.OtherOptions.HIJACK_HANDLE

        If CloakThreadCheck.Checked = True Then

            'Check Enum : Core.GHWrapper.ThreadCreationOptions for more options

            Flags += Core.GHWrapper.ThreadCreationOptions.HIDE_FROM_DEBUGGER
            Flags += Core.GHWrapper.ThreadCreationOptions.FAKE_START_ADDRESS

        End If

        If SelectedMODE = Core.GHWrapper.INJECTION_MODE.ManualMap Then

            'Check Enum :  Core.GHWrapper.ManualMapping for more options

            Flags += Core.GHWrapper.ManualMapping.Default

        End If

        WriteLog("Injecting " & IO.Path.GetFileNameWithoutExtension(DLLPath) & " Mode: " & SelectedMODE.ToString & " And Method: " & SelectedMethod.ToString, Color.Cyan)
        Await Task.Delay(1000)

        Dim TimeOUT As Integer = Val(NumericUpDown1.Value * 1000)

        Dim InjResult_Thread As Core.GHWrapper.InjectedEvent = New Core.GHWrapper.InjectedEvent(AddressOf InjResult)

        Core.GHWrapper.Inject(InjResult_Thread, Proc.Id, DLLPath.ToString, SelectedMODE, SelectedMethod, Flags, TimeOUT, True)

        Await Task.Delay(TimeOUT)

    End Sub

    Private Sub InjResult(ByVal DLL As String, ByVal Result As Integer)
        'This event is activated from the API C ++ therefore any code that writes here will be in another Thread.

        'To return to the thread of your application, simply use Me.BeginInvoke()

        ' https://learn.microsoft.com/es-es/dotnet/api/system.windows.forms.control.begininvoke?view=windowsdesktop-7.0

        ' That's why I function 'WriteLog' It is continent inside a 'BeginInvoke', if it was not, the application freezes or will not show results.

        Dim GetResultInfo As String = Core.GHWrapper.GetError(Result)

        If GetResultInfo = "SUCCESS" Then
            WriteLog(System.IO.Path.GetFileNameWithoutExtension(DLL) & " was injected successfully.", Color.Lime)
        Else
            WriteLog(System.IO.Path.GetFileNameWithoutExtension(DLL) & " Errors Occurred While Injecting. CODE: " & Result & " - INFO: " & GetResultInfo, Color.Red)
        End If

        If AutoExitCheck.Checked = True Then
            WriteLog("Closing in 4 seconds.", Color.Orange)
            System.Threading.Thread.Sleep(2000)
            Environment.Exit(0)
        End If

    End Sub

#End Region


End Class
