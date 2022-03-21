#pragma once
#include <afxcoll.h>
#include <assert.h>

#if _DEBUG
class Debugging
{{
public:
	static CString GetInterfaceName(CString s_Guid)
	{{
		// You could call Init() here but this class would not be thread safe anymore.
		assert(!Interfaces().IsEmpty());
		
		s_Guid.MakeUpper();
		CString s_Name;
		if (Interfaces().Lookup(s_Guid, s_Name))
			return s_Name;
		else
			return s_Guid;
	}}

	// {1}
	static void Init()
	{{
		if (!Interfaces().IsEmpty()) return;

{2}		
	}}
	
private:
	__forceinline static CMapStringToString& Interfaces()
	{{ 
		// Making the variable local avoids the need to declare a static class member in an additional CPP file.
		static CMapStringToString i_Map;
		return i_Map;
	}}
}};
#endif // _DEBUG
