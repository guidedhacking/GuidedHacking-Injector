#include "pch.h"

#include "Download Manager.h"

DownloadManager::DownloadManager(bool ForceRedownload)
{
    m_bForceRedownload = ForceRedownload;
}

DownloadManager::~DownloadManager()
{
    if (m_hInterruptEvent)
    {
        CloseHandle(m_hInterruptEvent);
    }
}

HRESULT __stdcall DownloadManager::QueryInterface(const IID & riid, void ** ppvObject)
{
    UNREFERENCED_PARAMETER(riid);
    UNREFERENCED_PARAMETER(ppvObject);

    return E_NOINTERFACE;
}

ULONG __stdcall DownloadManager::AddRef(void)
{
    return 1;
}

ULONG __stdcall DownloadManager::Release(void)
{
    return 1;
}

HRESULT __stdcall DownloadManager::OnStartBinding(DWORD dwReserved, IBinding * pib)
{
    UNREFERENCED_PARAMETER(dwReserved);
    UNREFERENCED_PARAMETER(pib);

    LOG(2, "DownloadManager: OnStartBinding\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetPriority(LONG * pnPriority)
{
    UNREFERENCED_PARAMETER(pnPriority);

    LOG(2, "DownloadManager: GetPriority\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnLowResource(DWORD reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    LOG(2, "DownloadManager: OnLowResource\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnStopBinding(HRESULT hresult, LPCWSTR szError)
{
    UNREFERENCED_PARAMETER(hresult);
    UNREFERENCED_PARAMETER(szError);

    LOG(2, "DownloadManager: OnStopBinding\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetBindInfo(DWORD * grfBINDF, BINDINFO * pbindinfo)
{
    LOG(2, "DownloadManager: GetBindInfo\n");

    if (m_bForceRedownload)
    {
        if (grfBINDF)
        {
            *grfBINDF = BINDF_GETNEWESTVERSION | BINDF_NEEDFILE;
        }

        if (pbindinfo)
        {
            pbindinfo->dwOptions        = BINDINFO_OPTIONS_WININETFLAG;
            pbindinfo->dwOptionsFlags   = INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD;
        }
    }

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed)
{
    UNREFERENCED_PARAMETER(grfBSCF);
    UNREFERENCED_PARAMETER(dwSize);
    UNREFERENCED_PARAMETER(pformatetc);
    UNREFERENCED_PARAMETER(pstgmed);

    LOG(2, "DownloadManager: OnDataAvailable\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnObjectAvailable(const IID & riid, IUnknown * punk)
{
    UNREFERENCED_PARAMETER(riid);
    UNREFERENCED_PARAMETER(punk);

    LOG(2, "DownloadManager: OnObjectAvailable\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText)
{
    UNREFERENCED_PARAMETER(ulStatusCode);
    UNREFERENCED_PARAMETER(szStatusText);

    if (m_hInterruptEvent && WaitForSingleObject(m_hInterruptEvent, 0) == WAIT_OBJECT_0)
    {
        LOG(2, "DownloadManager: Interrupting download\n");

        return E_ABORT;
    }

    if (ulProgressMax)
    {
        m_fProgress = (float)ulProgress / ulProgressMax;

        if (m_fProgress - m_fOldProgress >= 0.095f)
        {
            LOG(2, "DownloadManager: %2.0f%%\n", (double)100.0f * m_fProgress);
            m_fOldProgress = m_fProgress;
        }
    }

    return S_OK;
}

BOOL DownloadManager::SetInterruptEvent(HANDLE hInterrupt)
{
    if (m_hInterruptEvent)
    {
        if (!CloseHandle(m_hInterruptEvent))
        {
            LOG(2, "Failed to close previous interrupt handle object: %08X\n", GetLastError());
        }

        m_hInterruptEvent = nullptr;
    }

    LOG(2, "DownloadManager: New interrupt event specified\n");

    auto current_process = GetCurrentProcess();

    return DuplicateHandle(current_process, hInterrupt, current_process, &m_hInterruptEvent, NULL, FALSE, DUPLICATE_SAME_ACCESS);
}

float DownloadManager::GetDownloadProgress() const
{
    return m_fProgress;
}