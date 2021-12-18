#pragma once

#include "pch.h"

#include "Symbol Loader.h"

class SYMBOL_PARSER
{
	HANDLE m_hProcess;

	bool m_bInitialized;
	bool m_bReady;

	DWORD64 m_SymbolTable;

public:

	SYMBOL_PARSER();
	~SYMBOL_PARSER();

	DWORD Initialize(const SYMBOL_LOADER * pSymbolObject);
	void Cleanup();

	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);
};

inline SYMBOL_PARSER sym_parser;