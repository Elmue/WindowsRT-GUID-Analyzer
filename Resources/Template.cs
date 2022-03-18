using System;
using System.Collections.Generic;

#if DEBUG
public class Debugging
{{
	private static Dictionary<String,String> mi_Interfaces = new Dictionary<String,String>();

	public static String GetInterfaceName(String s_Guid)
	{{
		String s_Name;
		mi_Interfaces.TryGetValue(s_Guid.ToUpper(), out s_Name);
		return s_Name;
	}}
	
	// {1}
	static Debugging()
	{{
{2}
	}}
}}
#endif // DEBUG
