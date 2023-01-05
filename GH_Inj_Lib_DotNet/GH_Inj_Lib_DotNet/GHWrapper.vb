
Imports System.Runtime.InteropServices

Namespace Core

    Public Class GHWrapper

#Region " Pinvoke "

        <UnmanagedFunctionPointer(CallingConvention.Cdecl)>
        Public Delegate Sub InjectedEvent(ByVal DLL As String, ByVal Result As Integer)

        <UnmanagedFunctionPointer(CallingConvention.Cdecl)>
        Public Delegate Sub DownloadEnd()

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub DownloadAndImportSymbols(ByVal aCallback As DownloadEnd)
        End Sub

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function Ini() As Boolean
        End Function

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function GetModName() As String
        End Function

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function GetDownloadProgress(ByVal Isx64 As Boolean) As Single
        End Function

        Public Shared Function GetDownloadProgressEx(ByVal Isx64 As Boolean) As Integer
            Dim GetDownloadProgress As Single = Core.GHWrapper.GetDownloadProgress(Isx64)
            Dim ProgressEx As Integer = (GetDownloadProgress * 100) / Single.Parse("1.0")
            Return ProgressEx
        End Function

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub SetManualHook(ByVal HookName As String)
        End Sub

        <DllImport(API, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub Inject(ByVal aDLLCallback As InjectedEvent, ByVal TargetProcessId As UInteger, ByVal DllPathToInject As String, Optional ByVal INJECTION_MODE_Ex As UInteger = INJECTION_MODE.LoadLibrary, Optional ByVal LAUNCH_METHOD_Ex As UInteger = LAUNCH_METHOD.NtCreateThreadEx, Optional ByVal FlagsEx As UInteger = 0, Optional ByVal TimeoutEx As UInteger = 2000, Optional ByVal WritteLog As Boolean = True)
        End Sub

#End Region

#Region " Enum "

        <Flags>
        Public Enum DLLOptionsEx As UInteger
            KEEP_HEADER = &H0
            ERASE_HEADER = &H1
            FAKE_HEADER = &H2
        End Enum

        'Manual mapping options
        <Flags>
        Public Enum ManualMapping As UInteger
            STABLE = RUN_DLL_MAIN Or RESOLVE_IMPORTS Or SET_PAGE_PROTECTIONS
            [Default] = RESOLVE_IMPORTS Or RESOLVE_DELAY_IMPORTS Or
    INIT_SECURITY_COOKIE Or EXECUTE_TLS Or
    ENABLE_EXCEPTIONS Or RUN_DLL_MAIN Or
    SET_PAGE_PROTECTIONS
            CLEAN_DATA_DIR = &H10000 'removes data from the dlls PE header, ignored if SET_PAGE_PROTECTIONS is set
            RESOLVE_IMPORTS = &H20000 'resolves dll imports
            RESOLVE_DELAY_IMPORTS = &H40000 'resolves delayed imports
            EXECUTE_TLS = &H80000 'executes TLS callbacks and initializes static TLS data
            ENABLE_EXCEPTIONS = &H100000 'enables exception handling
            SET_PAGE_PROTECTIONS = &H200000 'sets page protections based on section characteristics, if set CLEAN_DATA_DIR will be ignored
            INIT_SECURITY_COOKIE = &H400000 'initializes security cookie for buffer overrun protection
            RUN_DLL_MAIN = &H800000 'executes DllMain
            RUN_UNDER_LDR_LOCK = &H1000000 'runs the DllMain under the loader lock
            SHIFT_MODULE_BASE = &H2000000 'shifts the module base by a random offset
        End Enum

        <Flags>
        Public Enum INJECTION_MODE
            LoadLibraryExW = 0
            LdrLoadDll = 1
            LdrpLoadDll = 2
            LdrpLoadDllInternal = 3
            ManualMap = 4
            LoadLibrary = 5
        End Enum

        'enum which is used to select the method to execute the shellcode
        <Flags>
        Public Enum LAUNCH_METHOD
            NtCreateThreadEx = 0
            HijackThread = 1
            SetWindowsHookEx = 2
            QueueUserAPC = 3
            KernelCallback = 4
            FakeVEH = 5
        End Enum

        <Flags>
        Public Enum OtherOptions
            UNLINK_FROM_PEB = &H4 'unlinks the module from the process enviroment block (1)
            THREAD_CREATE_CLOAKED = &H8 'induces CTF_FAKE_START_ADDRESS | CTF_HIDE_FROM_DEBUGGER (2), see thread creation options for more flags
            SCRAMBLE_DLL_NAME = &H10 'randomizes the dll name on disk before injecting it
            LOAD_DLL_COPY = &H20 'loads a copy of the dll from %temp% directory
            HIJACK_HANDLE = &H40 'tries to a hijack a handle from another process instead of using OpenProcess
        End Enum

        <Flags>
        Public Enum ThreadCreationOptions
            FAKE_START_ADDRESS = &H1000
            HIDE_FROM_DEBUGGER = &H2000
            SKIP_THREAD_ATTACH = &H4000
            FAKE_TEB_CLIENT_ID = &H8000
        End Enum

#End Region

#Region " Declare "

        Public Const API As String = "InjectionHelper.dll"

        Public Shared ErrorDictionary As IDictionary(Of Integer, String) = New Dictionary(Of Integer, String)() From {
    {&H0, "SUCCESS"},
    {&H1, "INJ_ERR_NO_DATA"},
    {&H2, "INJ_ERR_INVALID_FILEPATH"},
    {&H3, "INJ_ERR_STR_CONVERSION_TO_W_FAILED"},
    {&H4, "INJ_ERR_STRINGC_XXX_FAIL"},
    {&H5, "INJ_ERR_FILE_DOESNT_EXIST"},
    {&H6, "INJ_ERR_INVALID_PID"},
    {&H7, "INJ_ERR_CANT_OPEN_PROCESS"},
    {&H8, "INJ_ERR_INVALID_PROC_HANDLE"},
    {&H9, "INJ_ERR_CANT_GET_EXE_FILENAME"},
    {&HA, "INJ_ERR_PLATFORM_MISMATCH"},
    {&HB, "INJ_ERR_CANT_GET_TEMP_DIR"},
    {&HC, "INJ_ERR_CANT_COPY_FILE"},
    {&HD, "INJ_ERR_CANT_RENAME_FILE"},
    {&HE, "INJ_ERR_INVALID_INJ_METHOD"},
    {&HF, "INJ_ERR_REMOTE_CODE_FAILED"},
    {&H10, "INJ_ERR_WPM_FAIL"},
    {&H11, "INJ_ERR_RPM_FAIL"},
    {&H12, "INJ_ERR_GET_MODULE_HANDLE_FAIL"},
    {&H13, "INJ_ERR_CANT_FIND_MOD_PEB"},
    {&H14, "INJ_ERR_UNLINKING_FAILED"},
    {&H15, "INJ_ERR_OUT_OF_MEMORY_EXT"},
    {&H16, "INJ_ERR_OUT_OF_MEMORY_INT"},
    {&H17, "INJ_ERR_OUT_OF_MEMORY_NEW"},
    {&H18, "INJ_ERR_IMAGE_CANT_RELOC"},
    {&H19, "INJ_ERR_GET_SYMBOL_ADDRESS_FAILED"},
    {&H1A, "INJ_ERR_GET_PROC_ADDRESS_FAIL"},
    {&H1B, "INJ_ERR_VERIFY_RESULT_FAIL"},
    {&H1C, "INJ_ERR_SYMBOL_INIT_NOT_DONE"},
    {&H1D, "INJ_ERR_SYMBOL_INIT_FAIL"},
    {&H1E, "INJ_ERR_SYMBOL_GET_FAIL"},
    {&H1F, "INJ_ERR_CANT_GET_MODULE_PATH"},
    {&H20, "INJ_ERR_FAILED_TO_LOAD_DLL"},
    {&H21, "INJ_ERR_HIJACK_NO_HANDLES"},
    {&H22, "INJ_ERR_HIJACK_NO_NATIVE_HANDLE"},
    {&H23, "INJ_ERR_HIJACK_INJ_FAILED"},
    {&H24, "INJ_ERR_HIJACK_OUT_OF_MEMORY_EXT"},
    {&H25, "INJ_ERR_HIJACK_WPM_FAIL"},
    {&H26, "INJ_ERR_HIJACK_INJECTW_MISSING"},
    {&H27, "INJ_ERR_HIJACK_REMOTE_INJ_FAIL"},
    {&H28, "INJ_ERR_LLEXW_FAILED"},
    {&H29, "INJ_ERR_LDRLDLL_FAILED"},
    {&H2A, "INJ_ERR_LDRPLDLL_FAILED"},
    {&H2B, "INJ_ERR_LDRPLDLLINTERNAL_FAILED"},
    {&H2C, "INJ_ERR_CANT_GET_PEB"},
    {&H2D, "INJ_ERR_INVALID_PEB_DATA"},
    {&H2E, "INJ_ERR_UPDATE_PROTECTION_FAILED"},
    {&H2F, "INJ_ERR_WOW64_NTDLL_MISSING"},
    {&H30, "INJ_ERR_INVALID_PATH_SEPERATOR"},
    {&H31, "INJ_ERR_LDRP_PREPROCESS_FAILED"},
    {&H32, "INJ_ERR_INVALID_POINTER"},
    {&H33, "INJ_ERR_NOT_IMPLEMENTED"},
    {&H34, "INJ_ERR_KERNEL32_MISSING"},
    {&H400001, "INJ_MM_ERR_NO_DATA"},
    {&H400002, "INJ_MM_ERR_NT_OPEN_FILE"},
    {&H400003, "INJ_MM_ERR_HEAP_ALLOC"},
    {&H400004, "INJ_MM_ERR_NT_READ_FILE"},
    {&H400005, "INJ_MM_ERR_SET_FILE_POSITION"},
    {&H400006, "INJ_MM_ERR_UPDATE_PAGE_PROTECTION"},
    {&H400007, "INJ_MM_ERR_CANT_GET_FILE_SIZE"},
    {&H400008, "INJ_MM_ERR_MEMORY_ALLOCATION_FAILED"},
    {&H400009, "INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED"},
    {&H40000A, "INJ_MM_ERR_IMPORT_FAIL"},
    {&H40000B, "INJ_MM_ERR_DELAY_IMPORT_FAIL"},
    {&H40000C, "INJ_MM_ERR_ENABLING_SEH_FAILED"},
    {&H40000D, "INJ_MM_ERR_INVALID_HEAP_HANDLE"},
    {&H40000E, "INJ_MM_ERR_CANT_GET_PEB"},
    {&H40000F, "INJ_MM_ERR_INVALID_PEB_DATA"},
    {&H10000001, "SR_ERR_CANT_QUERY_SESSION_ID"},
    {&H10000002, "SR_ERR_INVALID_LAUNCH_METHOD"},
    {&H10000003, "SR_ERR_NOT_LOCAL_SYSTEM"},
    {&H10100001, "SR_NTCTE_ERR_NTCTE_MISSING"},
    {&H10100002, "SR_NTCTE_ERR_PROC_INFO_FAIL"},
    {&H10100003, "SR_NTCTE_ERR_CANT_ALLOC_MEM"},
    {&H10100004, "SR_NTCTE_ERR_WPM_FAIL"},
    {&H10100005, "SR_NTCTE_ERR_NTCTE_FAIL"},
    {&H10100006, "SR_NTCTE_ERR_GET_CONTEXT_FAIL"},
    {&H10100007, "SR_NTCTE_ERR_SET_CONTEXT_FAIL"},
    {&H10100008, "SR_NTCTE_ERR_RESUME_FAIL"},
    {&H10100009, "SR_NTCTE_ERR_REMOTE_TIMEOUT"},
    {&H1010000A, "SR_NTCTE_ERR_GECT_FAIL"},
    {&H1010000B, "SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL"},
    {&H1010000C, "SR_NTCTE_ERR_RPM_FAIL"},
    {&H10200001, "SR_HT_ERR_PROC_INFO_FAIL"},
    {&H10200002, "SR_HT_ERR_NO_THREADS"},
    {&H10200003, "SR_HT_ERR_OPEN_THREAD_FAIL"},
    {&H10200004, "SR_HT_ERR_SUSPEND_FAIL"},
    {&H10200005, "SR_HT_ERR_GET_CONTEXT_FAIL"},
    {&H10200006, "SR_HT_ERR_CANT_ALLOC_MEM"},
    {&H10200007, "SR_HT_ERR_WPM_FAIL"},
    {&H10200008, "SR_HT_ERR_SET_CONTEXT_FAIL"},
    {&H10200009, "SR_HT_ERR_RESUME_FAIL"},
    {&H1020000A, "SR_HT_ERR_REMOTE_TIMEOUT"},
    {&H1020000B, "SR_HT_ERR_REMOTE_PENDING_TIMEOUT"},
    {&H1020000C, "SR_HT_ERR_RPM_FAIL"},
    {&H10300001, "SR_SWHEX_ERR_CANT_OPEN_INFO_TXT"},
    {&H10300002, "SR_SWHEX_ERR_CANT_ALLOC_MEM"},
    {&H10300003, "SR_SWHEX_ERR_WPM_FAIL"},
    {&H10300004, "SR_SWHEX_ERR_WTSQUERY_FAIL"},
    {&H10300005, "SR_SWHEX_ERR_DUP_TOKEN_FAIL"},
    {&H10300006, "SR_SWHEX_ERR_GET_ADMIN_TOKEN_FAIL"},
    {&H10300007, "SR_SWHEX_ERR_CANT_CREATE_PROCESS"},
    {&H10300008, "SR_SWHEX_ERR_SWHEX_TIMEOUT"},
    {&H10300009, "SR_SWHEX_ERR_REMOTE_TIMEOUT"},
    {&H1030000A, "SR_SWHEX_ERR_RPM_FAIL"},
    {&H1030000B, "SR_SWHEX_ERR_SWHEX_EXT_ERROR"},
    {&H10400001, "SR_QUAPC_ERR_RTLQAW64_MISSING"},
    {&H10400002, "SR_QUAPC_ERR_CANT_ALLOC_MEM"},
    {&H10400003, "SR_QUAPC_ERR_WPM_FAIL"},
    {&H10400004, "SR_QUAPC_ERR_PROC_INFO_FAIL"},
    {&H10400005, "SR_QUAPC_ERR_NO_THREADS"},
    {&H10400006, "SR_QUAPC_ERR_REMOTE_TIMEOUT"},
    {&H10400007, "SR_QUAPC_ERR_RPM_FAIL"},
    {&H20000001, "FILE_ERR_CANT_OPEN_FILE"},
    {&H20000002, "FILE_ERR_INVALID_FILE_SIZE"},
    {&H20000003, "FILE_ERR_INVALID_FILE"},
    {&H30000001, "SM_ERR_INVALID_ARGC"},
    {&H30000002, "SM_ERR_INVALID_ARGV"},
    {&H30100001, "SWHEX_ERR_INVALID_PATH"},
    {&H30100002, "SWHEX_ERR_CANT_OPEN_FILE"},
    {&H30100003, "SWHEX_ERR_EMPTY_FILE"},
    {&H30100004, "SWHEX_ERR_INVALID_INFO"},
    {&H30100005, "SWHEX_ERR_ENUM_WINDOWS_FAIL"},
    {&H30100006, "SWHEX_ERR_NO_WINDOWS"},
    {&H40000001, "SYMBOL_ERR_CANT_OPEN_MODULE"},
    {&H40000002, "SYMBOL_ERR_FILE_SIZE_IS_NULL"},
    {&H40000003, "SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW"},
    {&H40000004, "SYMBOL_ERR_INVALID_FILE_ARCHITECTURE"},
    {&H40000005, "SYMBOL_ERR_CANT_ALLOC_MEMORY"},
    {&H40000006, "SYMBOL_ERR_NO_PDB_DEBUG_DATA"},
    {&H40000007, "SYMBOL_ERR_PATH_DOESNT_EXIST"},
    {&H40000008, "SYMBOL_ERR_CANT_CREATE_DIRECTORY"},
    {&H400000A8, "SYMBOL_ERR_CANT_CONVERT_PDB_GUID"},
    {&H40000009, "SYMBOL_ERR_GUID_TO_ANSI_FAILED"},
    {&H4000000A, "SYMBOL_ERR_DOWNLOAD_FAILED"},
    {&H4000000B, "SYMBOL_ERR_CANT_ACCESS_PDB_FILE"},
    {&H4000000C, "SYMBOL_ERR_CANT_OPEN_PDB_FILE"},
    {&H4000000D, "SYMBOL_ERR_CANT_OPEN_PROCESS"},
    {&H4000000E, "SYMBOL_ERR_SYM_INIT_FAIL"},
    {&H4000000F, "SYMBOL_ERR_SYM_LOAD_TABLE"},
    {&H40000010, "SYMBOL_ERR_ALREADY_INITIALIZED"},
    {&H40000011, "SYMBOL_ERR_NOT_INITIALIZED"},
    {&H40000012, "SYMBOL_ERR_IVNALID_SYMBOL_NAME"},
    {&H40000013, "SYMBOL_ERR_SYMBOL_SEARCH_FAILED"},
    {&H40000014, "SYMBOL_CANT_OPEN_PROCESS"},
    {&H40000015, "SYMBOL_ERR_COPYFILE_FAILED"},
    {&H40000016, "SYMBOL_ERR_INTERRUPT"},
    {&H50000001, "HOOK_SCAN_ERR_INVALID_PROCESS_ID"},
    {&H50000002, "HOOK_SCAN_ERR_CANT_OPEN_PROCESS"},
    {&H50000003, "HOOK_SCAN_ERR_PLATFORM_MISMATCH"},
    {&H50000004, "HOOK_SCAN_ERR_GETPROCADDRESS_FAILED"},
    {&H50000005, "HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED"},
    {&H50000006, "HOOK_SCAN_ERR_CANT_GET_OWN_MODULE_PATH"},
    {&H50000007, "HOOK_SCAN_ERR_CREATE_EVENT_FAILED"},
    {&H50000008, "HOOK_SCAN_ERR_CREATE_PROCESS_FAILED"},
    {&H50000009, "HOOK_SCAN_ERR_WAIT_FAILED"},
    {&H5000000A, "HOOK_SCAN_ERR_WAIT_TIMEOUT"},
    {&H5000000B, "HOOK_SCAN_ERR_BUFFER_TOO_SMALL"},
    {&H40000100, "UNDEFINE_ERR"}
}

#End Region

#Region " Public Methods "

        Public Shared Function GetError(ByVal ID As Integer) As String
            For Each ResultInfo As KeyValuePair(Of Integer, String) In ErrorDictionary
                If ResultInfo.Key = ID Then
                    Return ResultInfo.Value
                End If
            Next
            Return ID & "=Unknown"
        End Function

#End Region

    End Class

End Namespace

