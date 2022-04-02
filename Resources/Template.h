#pragma once

class Debugging
{{
public:
	// This function reads the interface name from an INI file.
	// If the GUID is unknown it will be returned unchanged.
	static CString GetInterfaceName(CString s_Guid, CString s_IniPath)
	{{
		WCHAR s_Buffer[1000]; // Some names have 300 characters!
		GetPrivateProfileStringW(L"All Interfaces", s_Guid, s_Guid, s_Buffer, 1000, s_IniPath);
		return s_Buffer;
	}}
}};

