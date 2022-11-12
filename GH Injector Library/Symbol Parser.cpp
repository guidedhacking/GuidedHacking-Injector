#include "pch.h"

#include "Symbol Parser.h"

SYMBOL_PARSER::SYMBOL_PARSER()
{

}

SYMBOL_PARSER::~SYMBOL_PARSER()
{
	Cleanup();
}

DWORD SYMBOL_PARSER::Initialize(const SYMBOL_LOADER * pSymbolObject)
{
	LOG(1, "SYMBOL_LOADER::Initialize\n");

	if (!pSymbolObject)
	{
		LOG(1, "SYMBOL_PARSER: symbol object is NULL\n");

		return SYMBOL_ERR_OBJECT_IS_NULL;
	}

	if (!pSymbolObject->IsReady())
	{
		LOG(1, "SYMBOL_PARSER: symbol object isn't ready\n");

		return SYMBOL_ERR_OBJECT_NOT_READY;
	}

	if (m_SymbolTable)
	{
		SymUnloadModule64(m_hProcess, m_SymbolTable);

		m_SymbolTable = 0;
	}

	if (!m_hProcess)
	{
		m_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
		if (!m_hProcess)
		{
			LOG(1, "SYMBOL_PARSER: can't open current process: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_OPEN_PROCESS;
		}
	}

	if (!m_bInitialized)
	{
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

		if (!SymInitializeW(m_hProcess, nullptr, FALSE))
		{
			CloseHandle(m_hProcess);

			LOG(1, "SYMBOL_PARSER: SymInitializeW failed: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_SYM_INIT_FAIL;
		}

		m_bInitialized = true;
	}

	m_SymbolTable = SymLoadModuleExW(m_hProcess, nullptr, pSymbolObject->GetFilepath().c_str(), nullptr, 0x10000000, pSymbolObject->GetFilesize(), nullptr, NULL);
	if (!m_SymbolTable)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);

		LOG(1, "SYMBOL_PARSER: SymLoadModuleExW failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYM_LOAD_TABLE;
	}

	m_bReady = true;

	LOG(1, "SYMBOL_PARSER: initialization finished\n");

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	if (!m_bReady)
	{
		LOG(2, "SYMBOL_PARSER: not ready\n");

		return SYMBOL_ERR_NOT_INITIALIZED;
	}

	if (!szSymbolName)
	{
		LOG(2, "SYMBOL_PARSER: invalid symbol name\n");

		return SYMBOL_ERR_IVNALID_SYMBOL_NAME;
	}

	SYMBOL_INFO si{ 0 };
	si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (!SymFromName(m_hProcess, szSymbolName, &si))
	{
		LOG(2, "SYMBOL_PARSER: search failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}

	RvaOut = (DWORD)(si.Address - si.ModBase);

	LOG(2, "SYMBOL_PARSER: RVA %08X -> %s\n", RvaOut, szSymbolName);

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_PARSER::Cleanup()
{
	LOG(1, "SYMBOL_PARSER::Cleanup\n");

	if (m_bInitialized)
	{
		if (m_SymbolTable)
		{
			SymUnloadModule64(m_hProcess, m_SymbolTable);

			m_SymbolTable = 0;
		}

		SymCleanup(m_hProcess);

		m_bInitialized = false;
	}

	if (m_hProcess)
	{
		CloseHandle(m_hProcess);

		m_hProcess = nullptr;
	}
}