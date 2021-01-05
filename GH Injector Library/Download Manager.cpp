#include "pch.h"

#include "Download Manager.h"

DownloadManager::DownloadManager()
{
    m_hInterruptEvent   = nullptr;
    m_fProgress         = 0.0f;
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

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetPriority(LONG * pnPriority)
{
    UNREFERENCED_PARAMETER(pnPriority);

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnLowResource(DWORD reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnStopBinding(HRESULT hresult, LPCWSTR szError)
{
    UNREFERENCED_PARAMETER(hresult);
    UNREFERENCED_PARAMETER(szError);

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetBindInfo(DWORD * grfBINDF, BINDINFO *pbindinfo)
{
    UNREFERENCED_PARAMETER(grfBINDF);
    UNREFERENCED_PARAMETER(pbindinfo);

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed)
{
    UNREFERENCED_PARAMETER(grfBSCF);
    UNREFERENCED_PARAMETER(dwSize);
    UNREFERENCED_PARAMETER(pformatetc);
    UNREFERENCED_PARAMETER(pstgmed);

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnObjectAvailable(const IID & riid, IUnknown * punk)
{
    UNREFERENCED_PARAMETER(riid);
    UNREFERENCED_PARAMETER(punk);

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText)
{
    UNREFERENCED_PARAMETER(ulStatusCode);
    UNREFERENCED_PARAMETER(szStatusText);

    if (m_hInterruptEvent && WaitForSingleObject(m_hInterruptEvent, 0) == WAIT_OBJECT_0)
    {
        return E_ABORT;
    }

    if (ulProgressMax)
    {
        m_fProgress = (float)ulProgress / ulProgressMax;
    }

    return S_OK;
}

BOOL DownloadManager::SetInterruptEvent(HANDLE hInterrupt)
{
    if (m_hInterruptEvent)
    {
        CloseHandle(m_hInterruptEvent);
    }

    LOG("New interrupt event specified\n");

    return DuplicateHandle(GetCurrentProcess(), hInterrupt, GetCurrentProcess(), &m_hInterruptEvent, NULL, FALSE, DUPLICATE_SAME_ACCESS);
}

float DownloadManager::GetDownloadProgress()
{
    return m_fProgress;
}
