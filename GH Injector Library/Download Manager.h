/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

//Stolen from here:
//https://stackoverflow.com/a/5292277
//by User Hans Passant

#pragma once

#include "pch.h"

class DownloadManager : public IBindStatusCallback
{
    HANDLE  m_hInterruptEvent   = nullptr;
    float   m_fProgress         = 0.0f;
    float   m_fOldProgress      = 0.0f;
    bool    m_bForceRedownload  = false;

public:

    DownloadManager(bool ForceRedownload = true);

    ~DownloadManager();

    HRESULT __stdcall QueryInterface(const IID & riid, void ** ppvObject);

    ULONG STDMETHODCALLTYPE AddRef();

    ULONG STDMETHODCALLTYPE Release();

    virtual HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD dwReserved, IBinding * pib);

    virtual HRESULT STDMETHODCALLTYPE GetPriority(LONG * pnPriority);

    virtual HRESULT STDMETHODCALLTYPE OnLowResource(DWORD reserved);

    virtual HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT hresult, LPCWSTR szError);

    virtual HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD * grfBINDF, BINDINFO * pbindinfo);

    virtual HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed);

    virtual HRESULT STDMETHODCALLTYPE OnObjectAvailable(const IID & riid, IUnknown * punk);

    HRESULT __stdcall OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText);

    BOOL SetInterruptEvent(HANDLE hInterrupt);

    float GetDownloadProgress() const;
};