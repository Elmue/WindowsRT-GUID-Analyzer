using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace GuidAnalyzer
{
    class Program
    {
        static int    SDK_BUILD  = 22000;
        static String SDK_PATH   = "E:\\Windows SDK\\Include\\10.0." + SDK_BUILD + ".0\\";
        static bool   ONLY_WINRT = false; // true -> scan only SDK subfolder winrt, false -> scan all Windows COM interfaces
        static String OUT_PATH   = Path.GetDirectoryName(Application.ExecutablePath) + "\\";

        static void Main(string[] args)
        {
            try
            {
                // read 4086 classes in 414 DLL's
                ParseRegistry();

                // read 7854 interfaces
                ParseHeaderFiles();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("\nException: " + Ex.Message);
            }

            Console.WriteLine("\nPress a key");
            Console.ReadKey();
        }

        static void ParseHeaderFiles()
        {
            if (!Directory.Exists(SDK_PATH))
            {
                Console.WriteLine("\nDirectory does not exist: " + SDK_PATH);
                return;
            }

            Console.WriteLine();
            SortedList<String, String> i_Interfaces = new SortedList<String, String>();

            // These SDK subfolders contain all documented Windows interface declarations
            foreach (String s_SubDir in new String[] { "winrt", "um", "shared" })
            {
                if (ONLY_WINRT && s_SubDir != "winrt")
                    continue;

                Console.Write("**** Parsing SDK Header Files (subfolder "+s_SubDir+"). Please wait...\n");

                foreach (String s_Path in Directory.EnumerateFiles(SDK_PATH + s_SubDir, "*.h"))
                {
                    String s_FileName = s_SubDir + "\\" + Path.GetFileName(s_Path);
                    String[] s_Lines  = File.ReadAllLines(s_Path);

                    for (int L=0; L<s_Lines.Length; L++)
                    {
                        String s_Line = s_Lines[L].Trim();

                        // Interface declaration in 2 lines:
                        // MIDL_INTERFACE("00000035-0000-0000-C000-000000000046")
                        // IActivationFactory : public IInspectable
                        if (s_Line.StartsWith("MIDL_INTERFACE"))
                        {
                            int s32_FirstLine = L;

                            String s_GUID = ExtractBetween(s_Line, "(", ")");
                            if (s_GUID == null)
                            {
                                Console.WriteLine("Syntax Error (A) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            s_Line = GetNextValidLine(s_Lines, ref L);
                            if (s_Line == null)
                            {
                                Console.WriteLine("Syntax Error (B) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            String[] s_Parts = s_Line.Split(':');
                            if (s_Parts.Length != 2)
                            {
                                // IUnknown is not derived from another interface --> no ':' contained
                                if (s_Line != "IUnknown")
                                {
                                    Console.WriteLine("Syntax Error (C) in line " + L + " in " + s_FileName);
                                    continue;   
                                }
                            }

                            String s_Namespace = FindNamespace(s_Lines, s32_FirstLine);
                            String s_FullName  = s_Namespace + s_Parts[0].Trim('"', ' ');

                            AddInterface(i_Interfaces, s_GUID, s_FullName);
                        }

                        // Interface declaration in 1 line:
                        // DECLARE_INTERFACE_IID_(ICompositorInterop, IUnknown, "25297D5C-3AD4-4C9C-B5CF-E36A38512330")
                        else if (s_Line.StartsWith("DECLARE_INTERFACE_IID_")) // FIRST
                        {
                            String s_Parenth = ExtractBetween(s_Line, "(", ")");
                            if (s_Parenth == null)
                            {
                                Console.WriteLine("Syntax Error (D) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            String[] s_Parts = s_Parenth.Split(',');
                            if (s_Parts.Length != 3)
                            {
                                Console.WriteLine("Syntax Error (E) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            AddInterface(i_Interfaces, s_Parts[2], s_Parts[0]);
                        }

                        // Interface declaration in 1 line:
                        // DECLARE_INTERFACE_IID(IFileViewerA, "000214f0-0000-0000-c000-000000000046")
                        else if (s_Line.StartsWith("DECLARE_INTERFACE_IID")) // AFTER
                        {
                            String s_Parenth = ExtractBetween(s_Line, "(", ")");
                            if (s_Parenth == null)
                            {
                                Console.WriteLine("Syntax Error (F) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            String[] s_Parts = s_Parenth.Split(',');
                            if (s_Parts.Length != 2)
                            {
                                Console.WriteLine("Syntax Error (G) in line " + L + " in " + s_FileName);
                                continue;
                            }

                            AddInterface(i_Interfaces, s_Parts[1], s_Parts[0]);
                        }
                    }
                }
            }

            WriteInterfaces(i_Interfaces, SDK_BUILD);
        }

        static String ExtractBetween(String s_Line, String s_Start, String s_End)
        {
            if (s_Line == null)
                return null;

            int s32_Start = s_Line.IndexOf(s_Start);
            if (s32_Start < 0)
                return null;

            s32_Start += s_Start.Length;

            int s32_End = s_Line.IndexOf(s_End, s32_Start);
            if (s32_End < 0)
                return null;

            return s_Line.Substring(s32_Start, s32_End - s32_Start);
        }

        static String GetNextValidLine(String[] s_Lines, ref int L)
        {
            for (int N=0; true; N++)
            {
                L ++;
                if (L >= s_Lines.Length || N > 5)
                    return null;

                String s_Line = s_Lines[L].Trim();
                if (IsLineValid(s_Line))
                    return s_Line;
            }
        }

        /// <summary>
        ///            MIDL_INTERFACE("7ae1fa72-029e-4dc5-a2f8-5fb763154150")
        /// #if WINDOWS_AI_MACHINELEARNING_PREVIEW_MACHINELEARNINGPREVIEWCONTRACT_VERSION >= 0x20000
        ///            DEPRECATED("Use IImageFeatureDescriptor instead of IImageVariableDescriptorPreview. For more info, see MSDN.")
        /// #endif // WINDOWS_AI_MACHINELEARNING_PREVIEW_MACHINELEARNINGPREVIEWCONTRACT_VERSION >= 0x20000
        ///            IImageVariableDescriptorPreview : public IInspectable
        /// </summary>
        static bool IsLineValid(String s_Line)
        {
            // s_Line is already trimmed
            if (s_Line.Length == 0            ||
                s_Line.StartsWith("#if")      || 
                s_Line.StartsWith("#endif")   || 
                s_Line.StartsWith("#define")  || 
                s_Line.StartsWith("/*")       || 
                s_Line.StartsWith("*/")       || 
                s_Line.StartsWith("{")        || 
                s_Line.StartsWith("}")        || 
                s_Line.StartsWith("DEPRECATED"))
                return false;

            return true;
        }

        /// <summary>
        /// namespace ABI {
        ///    namespace Windows {
        ///       namespace UI {
        ///          namespace WebUI {
        ///             MIDL_INTERFACE("2b09a173-b68e-4def-88c1-8de84e5aab2f")
        /// </summary>
        static String FindNamespace(String[] s_Lines, int L)
        {
            String s_Return = "";

            for (int i=0; i<8; i++)
            {
                String s_Line;
                for (int N=0; true; N++)
                {
                    L --;
                    if (L < 0 || N > 7)
                        return "";

                    s_Line = s_Lines[L].Trim();
                    if (s_Line.StartsWith("namespace"))
                        break;
                }

                String s_Namespace = ExtractBetween(s_Line, "namespace", "{");
                if (s_Namespace == null)
                    return "";

                s_Namespace = s_Namespace.Trim();

                s_Return = s_Namespace + "." + s_Return;
                if (s_Namespace == "ABI")
                    return s_Return;
            }
            return "";
        }

        static void AddInterface(SortedList<String, String> i_Interfaces, String s_Guid, String s_Name)
        {
            s_Guid = s_Guid.Trim('"', ' ', '{', '}').ToUpper();
            s_Name = s_Name.Trim('"', ' ');

            if (s_Guid.Length != 36 || s_Guid[8] != '-' || s_Guid[13] != '-' || s_Guid[18] != '-' || s_Guid[23] != '-')
            {
                Console.WriteLine("Invalid GUID: " + s_Guid);
                return;
            }

            // --> concat multiple GUID's for the same interface name with a tab character.
            String s_ExistGuid;
            if (i_Interfaces.TryGetValue(s_Name, out s_ExistGuid))
            {
                if (s_ExistGuid.Contains(s_Guid))
                    return;

                s_Guid += '\t' + s_ExistGuid;
            }
                        
            i_Interfaces[s_Name] = s_Guid;
        }

        static void WriteTextFile(String s_FileName, String s_WinVer, String s_Text)
        {
            String s_Path = OUT_PATH + s_WinVer + " " + s_FileName;
            File.WriteAllText(s_Path, s_Text, Encoding.UTF8);
            Console.WriteLine("File saved: " + s_Path);
        }

        static String GetHtmlHeader(String s_Title, String s_Comment)
        {
            return String.Format("<!DOCTYPE html>\r\n"
                               + "<html>\r\n"
                               + "<head>\r\n"
                               + "  <title>{0}</title>\r\n"
                               + "  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\r\n"
                               + "  <style>\r\n"
                               + "    table    {{ font-family: Courier New; font-size:14px; }}\r\n"
                               + "    td       {{ padding-left:4px; padding-right:4px; }}\r\n"
                               + "    h4       {{ color:blue; }}\r\n"
                               + "    .Comment {{ color:darkred; }}\r\n"
                               + "  </style>\r\n"
                               + "</head>\r\n"
                               + "<body>\r\n"
                               + "<h2>{0}</h2>\r\n"
                               + "<div class='Comment'>{1}</div>\r\n", s_Title, s_Comment);
        }

        static String GetXmlHeader(String s_Title, String s_Comment)
        {
            return String.Format("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                               + "<Xml>\r\n"
                               + "  <Title>{0}</Title>\r\n"
                               + "  <Comment>{1}</Comment>\r\n", s_Title, s_Comment);
        }

        static String GetWindowsVersion(int s32_Build)
        {
            String s_Ver = "8";
                 if (s32_Build >= 22000) s_Ver = "11";
            else if (s32_Build >= 10000) s_Ver = "10";
            return String.Format("Windows {0} (Build {1})", s_Ver, s32_Build);
        }

        /// <summary>
        /// Write an INI and a HTML file
        /// </summary>
        static void WriteInterfaces(SortedList<String, String> i_Interfaces, int s32_Build)
        {
            String s_Title   = ONLY_WINRT ? "WinRT Interfaces" : "All Interfaces";
            String s_WinVer  = GetWindowsVersion(s32_Build);
            String s_Comment = String.Format("{0} interfaces automatically extracted from the {1} SDK header files",
                                             i_Interfaces.Count, s_WinVer);

            StringBuilder s_Ini = new StringBuilder();
            StringBuilder s_Xml = new StringBuilder();
            StringBuilder s_Htm = new StringBuilder();

            s_Ini.AppendFormat("; {0}\r\n[{1}]\r\n", s_Comment, s_Title);

            s_Xml.Append(GetXmlHeader(s_Title, s_Comment));
            s_Xml.Append("  <Interfaces>\r\n");

            s_Htm.Append(GetHtmlHeader(s_Title, s_Comment));
            s_Htm.Append("<div>&nbsp;</div>\r\n");
            s_Htm.Append("<table border='1' cellspacing='0' cellpadding='0'>\r\n");

            foreach (KeyValuePair<String, String> i_Pair in i_Interfaces)
            { 
                foreach (String s_Guid in i_Pair.Value.Split('\t'))
                {
                    s_Ini.AppendFormat("{0} = {1}\r\n",                                   s_Guid, i_Pair.Key);
                    s_Xml.AppendFormat("    <Interface GUID=\"{0}\" Name=\"{1}\" />\r\n", s_Guid, i_Pair.Key);
                    s_Htm.AppendFormat("  <tr><td>{0}</td><td>{1}</td></tr>\r\n",         s_Guid, i_Pair.Key);
                }
            }

            s_Xml.Append("  </Interfaces>\r\n");
            s_Xml.Append("</Xml>\r\n");

            s_Htm.Append("</table>\r\n</body>\r\n</html>\r\n");

            WriteTextFile(s_Title + ".ini", s_WinVer, s_Ini.ToString());
            WriteTextFile(s_Title + ".xml", s_WinVer, s_Xml.ToString());
            WriteTextFile(s_Title + ".htm", s_WinVer, s_Htm.ToString());
        }

        // ====================================================================================

        static void ParseRegistry()
        {
            Console.Write("\n**** Parsing Registry. Please wait...\n");

            const String REG_PATH = @"Software\Microsoft\WindowsRuntime\ActivatableClassId";

            int s32_TotCount = 0;
            SortedList<String, List<String>> i_Dlls = new SortedList<String, List<String>>(StringComparer.InvariantCultureIgnoreCase);

            // On a 32 bit Windows the 64 bit Hive is ignored
            using (RegistryKey i_HKLM = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey i_Main = i_HKLM.OpenSubKey(REG_PATH))
            {
                foreach (String s_Class in i_Main.GetSubKeyNames())
                {
                    using (RegistryKey i_Sub = i_Main.OpenSubKey(s_Class))
                    {
                        String s_DllPath = (String)i_Sub.GetValue("DllPath", null);
                        if (s_DllPath == null)
                        {
                            // TODO: Read "Server" and add it to a separate list
                            continue;
                        }

                        List<String> i_ClassesList;
                        if (!i_Dlls.TryGetValue(s_DllPath, out i_ClassesList))
                        {
                            i_ClassesList = new List<string>();
                            i_Dlls.Add(s_DllPath, i_ClassesList);
                        }

                        i_ClassesList.Add(s_Class);
                        s32_TotCount ++;
                    }
                }
            }

            // Safe get Windows build number
            FileVersionInfo k_Info = FileVersionInfo.GetVersionInfo(Environment.SystemDirectory + "\\Kernel32.dll");
            WriteActivationDlls(i_Dlls, s32_TotCount, k_Info.ProductBuildPart);
        }

        /// <summary>
        /// Write an INI and a HTML file
        /// </summary>
        static void WriteActivationDlls(SortedList<String, List<String>> i_Dlls, int s32_TotCount, int s32_Build)
        {
            String s_WinVer  = GetWindowsVersion(s32_Build);
            String s_Comment = String.Format("{0} Activatable Classes automatically extracted from the {1} Registry",
                                             s32_TotCount, s_WinVer);

            StringBuilder s_Ini = new StringBuilder();
            StringBuilder s_Xml = new StringBuilder();
            StringBuilder s_Htm = new StringBuilder();

            s_Ini.AppendFormat("; {0}\r\n", s_Comment);
            s_Xml.Append(GetXmlHeader ("WinRT Activatable Classes", s_Comment));
            s_Htm.Append(GetHtmlHeader("WinRT Activatable Classes", s_Comment));

            s_Xml.Append("  <DLLs>\r\n");

            foreach (KeyValuePair<String, List<String>> i_Pair in i_Dlls)
            {
                s_Ini.AppendFormat("\r\n[{0}]\r\n",              i_Pair.Key);
                s_Xml.AppendFormat("    <DLL Path=\"{0}\">\r\n", i_Pair.Key);
                s_Htm.AppendFormat("<h4>{0}</h4>\r\n",           i_Pair.Key);
                s_Htm.Append("<table border='1' cellspacing='0' cellpadding='0'>\r\n");

                i_Pair.Value.Sort();
                for (int C=0; C<i_Pair.Value.Count; C++)
                {
                    String s_Class = i_Pair.Value[C];
                    s_Ini.AppendFormat("Class_{0} = {1}\r\n",                     C+1, s_Class);
                    s_Htm.AppendFormat("  <tr><td>{0}</td><td>{1}</td></tr>\r\n", C+1, s_Class);
                    s_Xml.AppendFormat("      <Class Name=\"{0}\" />\r\n",             s_Class);
                }

                s_Xml.Append("    </DLL>\r\n");
                s_Htm.Append("</table>\r\n");
            }

            s_Xml.Append("  </DLLs>\r\n");
            s_Xml.Append("</Xml>\r\n");

            s_Htm.Append("</body>\r\n</html>\r\n");

            WriteTextFile("WinRT Activatable Classes.ini", s_WinVer, s_Ini.ToString());
            WriteTextFile("WinRT Activatable Classes.xml", s_WinVer, s_Xml.ToString());
            WriteTextFile("WinRT Activatable Classes.htm", s_WinVer, s_Htm.ToString());
        }
    }
}
