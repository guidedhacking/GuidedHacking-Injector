Imports System.ComponentModel
Imports GH_Inj_Lib_DotNet

Public Class SymbolsDownloader

    Public Property EngineDLL As String = String.Empty
    Public Property Is64 As Boolean = False
    Private DI As New Core.DynamicInvoke

    Private IsFinalized As Boolean = False

    Private Sub SymbolsDownloader_Closing(sender As Object, e As CancelEventArgs) Handles Me.Closing
        If IsFinalized = False Then
            If MessageBox.Show("Are you sure you want to cancel the download?", "Symbols Downloader", MessageBoxButtons.YesNo) = DialogResult.Yes Then
                DI.Invoke("InterruptDownload", EngineDLL, GetType(Boolean), Nothing)
                System.Threading.Thread.Sleep(500)
                Me.DialogResult = DialogResult.Cancel
            Else
                e.Cancel = True
            End If
        End If
    End Sub

    Private Sub SymbolsDownloader_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        Label1.Text = "Downloading Symbols... "
    End Sub

    Private Sub SymbolsDownloader_Shown(sender As Object, e As EventArgs) Handles Me.Shown
        DI.Invoke("StartDownload", EngineDLL, GetType(Boolean), Nothing)
        System.Threading.Thread.Sleep(500)
        Timer1.Enabled = True
    End Sub

    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        Dim GetSymbolState As IntPtr = DI.Invoke("GetSymbolState", EngineDLL, GetType(IntPtr), Nothing)
        Dim GetImportState As IntPtr = DI.Invoke("GetImportState", EngineDLL, GetType(IntPtr), Nothing)

        Dim GetDownloadProgress As Integer = Core.GHWrapper.GetDownloadProgressEx(Is64)
        ProgressBar1.Value = GetDownloadProgress

        If GetSymbolState.ToInt32 = 0 Then
            'SymbolState Loaded
        End If

        If GetImportState.ToInt32 = 0 Then
            'ImportState Loaded
            IsFinalized = True
            Timer1.Enabled = False
            Me.DialogResult = DialogResult.OK
            Me.Close()
        End If

    End Sub
End Class