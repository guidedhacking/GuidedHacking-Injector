//Stolen from here:
//https://stackoverflow.com/a/5292277
//by User Hans Passant

#pragma once

#include "pch.h"

class DownloadManager : public IBindStatusCallback
{
    HANDLE  m_hInterruptEvent;
    float   m_fProgress;

public:

    DownloadManager();

    ~DownloadManager();

    HRESULT __stdcall QueryInterface(const IID & riid, void ** ppvObject);

    ULONG STDMETHODCALLTYPE AddRef(void);

    ULONG STDMETHODCALLTYPE Release(void);

    virtual HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD dwReserved, IBinding * pib);

    virtual HRESULT STDMETHODCALLTYPE GetPriority(LONG * pnPriority);

    virtual HRESULT STDMETHODCALLTYPE OnLowResource(DWORD reserved);

    virtual HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT hresult, LPCWSTR szError);

    virtual HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD * grfBINDF, BINDINFO *pbindinfo);

    virtual HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed);

    virtual HRESULT STDMETHODCALLTYPE OnObjectAvailable(const IID & riid, IUnknown * punk);

    HRESULT __stdcall OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText);

    BOOL SetInterruptEvent(HANDLE hInterrupt);

    float GetDownloadProgress();
};