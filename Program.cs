using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
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

        // =====================================================================================================================

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
                if (i_Main == null)
                {
                    Console.WriteLine("Registry key 'ActivatableClassId' does not exist.");
                    return;
                }

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

            Console.WriteLine("\n" + s32_TotCount + " activatable classes found.\r\n");

            // Safe get Windows build number
            FileVersionInfo k_Info = FileVersionInfo.GetVersionInfo(Environment.SystemDirectory + "\\Kernel32.dll");
            WriteActivationDlls(i_Dlls, s32_TotCount, k_Info.ProductBuildPart);
        }

        static void ParseHeaderFiles()
        {
            Console.WriteLine();
            SortedList<String, String> i_Interfaces = new SortedList<String, String>();
            SortedList<String, String> i_Guids      = new SortedList<String, String>();
            Dictionary<String, String> i_Ambiguous  = new Dictionary<String, String>();
            int s32_FileCount = 0;

            // These SDK subfolders contain all documented Windows interface declarations
            foreach (String s_SubDir in new String[] { 
                                                      "winrt", 
                                                     @"cppwinrt\winrt", 
                                                     @"cppwinrt\winrt\impl", 
                                                      "um", 
                                                      "shared" 
                                                      })
            {
                bool b_WinRT = s_SubDir.Contains("winrt");
                if (ONLY_WINRT && !b_WinRT)
                    continue;

                String s_Folder = SDK_PATH + s_SubDir;
                if (!Directory.Exists(s_Folder))
                {
                    Console.WriteLine("Directory does not exist: " + s_Folder);
                    continue;
                }

                Console.Write("**** Parsing SDK Header Files (subfolder '"+s_SubDir+"').  Please wait...\n");

                foreach (String s_Path in Directory.EnumerateFiles(s_Folder, "*.h"))
                {
                    s32_FileCount ++;
                    String s_FileName = s_SubDir + "\\" + Path.GetFileName(s_Path);

                    String[] s_Lines = File.ReadAllLines(s_Path);
                    PreProcessLines(ref s_Lines);

                    for (int L=0; L<s_Lines.Length; L++)
                    {
                        int s32_FirstLine = L;
                        String s_Line = s_Lines[L];
                        String s_GUID = null;

                        if (!IsLineValid(s_Line))
                            continue; // Line is empty, #define, #if,...

                        // CLSID defined in multiple lines:
                        // static const UUID D3D12ExperimentalShaderModels = { 
                        //     0x76f5573e,
                        //     0xf13a,
                        //     0x40f5,
                        //     { 0xb2, 0x97, 0x81, 0xce, 0x9e, 0x18, 0x93, 0x3f }
                        // };
                        if (s_Line.StartsWith("static const UUID "))
                        {
                            s_Line = s_Line.Substring(17);

                            String[] s_Parts = s_Line.Split('=');
                            if (s_Parts.Length == 2)
                                s_GUID = ExtractHexGuidMultiLine(s_Lines, ref L);

                            if (s_GUID != null)
                            {
                                AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                             
                            Console.WriteLine("Syntax Error in line " + (s32_FirstLine +1) + " in " + s_FileName);
                            continue;
                        }

                        // DEFINE_GUID(IID_IScriptNode, 0xaee2a94, 0xbcbb, 0x11d0, 0x8c, 0x72, 0x0, 0xc0, 0x4f, 0xc2, 0xb0, 0x85);
                        // ----------------------------------------------------------
                        // DEFINE_GUID(CLSID_AMMultiMediaStream, 
                        // 0x49c47ce5, 0x9ba4, 0x11d0, 0x82, 0x12, 0x00, 0xc0, 0x4f, 0xc3, 0x2c, 0x45);
                        // ----------------------------------------------------------
                        // DEFINE_GUIDEX(IID_IKsPinEx);
                        if (s_Line.StartsWith("DEFINE_GUID")       && 
                           !s_Line.Contains  ("DEFINE_GUIDSTRUCT") && // different syntax, see below
                           !s_Line.Contains  ("DEFINE_GUIDEX"))
                        {
                            String[] s_Parts = ExtractBetweenParenthesis(s_Lines, ref L, 12);
                            if (s_Parts != null)
                            {
                                s_GUID = HexListToGuid(s_Parts, 1); // skip first part
                                if (s_GUID != null)
                                {
                                    AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                    continue;
                                }
                            }
                               
                            // Skip already defined GUIDs in ksproxy.h
                            // DEFINE_GUID(IID_IKsPropertySet, STATIC_IID_IKsPropertySet);
                            // DEFINE_GUID(CLSID_Proxy, STATIC_CLSID_Proxy);
                            if (s_Line.Contains("STATIC_IID_") || s_Line.Contains("STATIC_CLSID_"))
                                continue;
                                    
                            Console.WriteLine("Syntax Error in line " + (s32_FirstLine +1) + " in " + s_FileName);
                            continue;
                        }

                        // template <> inline constexpr guid guid_v<Windows::AI::MachineLearning::IImageFeatureDescriptor>{ 0x365585A5,0x171A,0x4A2A,{ 0x98,0x5F,0x26,0x51,0x59,0xD3,0x89,0x5A } };
                        int s32_ConstExpr = s_Line.IndexOf("inline constexpr guid");
                        if (s32_ConstExpr > 0)
                        {
                            int s32_Start = s_Line.IndexOf("<", s32_ConstExpr);
                            int s32_End   = s_Line.LastIndexOf(">");
                            if (s32_Start > 0 && s32_End > s32_Start)
                            {
                                String s_Interface = s_Line.Substring(s32_Start + 1, s32_End - s32_Start - 1).Replace("::", ".");
                                s_GUID = ExtractHexGuidInline(s_Line);

                                if (s_Interface.Length > 3 && s_GUID != null)
                                {
                                    if (b_WinRT && s_Interface.Contains(".") && !s_Interface.StartsWith("ABI."))
                                        s_Interface = "ABI." + s_Interface;

                                    AddInterface(s_GUID, s_Interface, i_Interfaces, i_Guids, i_Ambiguous);
                                    continue;
                                }
                            }

                            // There are several lines without GUID. This is not an error.
                            if (s_GUID != null)
                                Console.WriteLine("Syntax Error in line " + (s32_FirstLine +1) + " in " + s_FileName);

                            continue;
                        }

                        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

                        Match i_Match = Regex.Match(s_Line, "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}");
                        if (!i_Match.Success)
                            continue; // Line does not contain a GUID

                        s_GUID = i_Match.Value.ToUpper();

                        // This is a special case: The name is the **second** word after the GUID:
                        // typedef DECLSPEC_UUID("4A249B72-FC9A-11d1-8B1E-00600806D9B6") 
                        // enum WbemChangeFlagEnum
                        // ----------------------------------------------------------------
                        // [uuid(905a0fef-bc53-11df-8c49-001e4fc686da)]
                        // struct IBufferByteAccess : public IUnknown
                        if (s_Line.StartsWith("typedef DECLSPEC_UUID") || // BEFORE s_Line.Contains("DECLSPEC_UUID") below !
                            s_Line.Contains  ("[uuid("))
                        {
                            int s32_Start = i_Match.Index + s_GUID.Length;
                            String s_Type = ExtractNextWord(s_Lines, ref L, ref s32_Start);

                            // s_Type = "enum", "struct", "__int64", "long", "DWORD",....
                            if (s_Type.Length > 0)
                            {
                                String s_Name = ExtractNextWord(s_Lines, ref L, ref s32_Start);
                                AddInterface(s_GUID, s_Name, i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // MIDL_INTERFACE("00000035-0000-0000-C000-000000000046")
                        // IActivationFactory : public IInspectable
                        // ----------------------------------------------------------
                        // class DECLSPEC_UUID("0BFCC060-8C1D-11d0-ACCD-00AA0060275C")
                        // DebugHelper;
                        // ----------------------------------------------------------
                        // DECLSPEC_UUID("17CCA71B-ECD7-11D0-B908-00A0C9223196") CLSID_Proxy;
                        // ----------------------------------------------------------
                        // class DECLSPEC_UUID("E2AE5372-5D40-11D2-960E-00C04F8EE628")
                        // SpNotifyTranslator;
                        // ----------------------------------------------------------
                        // typedef interface DECLSPEC_UUID("e3acb9d7-7ec2-4f0c-a0da-e81e0cbbe628")
                        // IDebugClient5* PDEBUG_CLIENT5;
                        // ----------------------------------------------------------
                        // interface DX_DECLARE_INTERFACE("2cd90691-12e2-11dc-9fed-001143a055f9") ID2D1Resource : public IUnknown
                        // ----------------------------------------------------------
                        // interface DWRITE_DECLARE_INTERFACE("727cad4e-d6af-4c9e-8a08-d695b11caa49") IDWriteFontFileLoader : public IUnknown
                        // ----------------------------------------------------------
                        // interface DML_DECLARE_INTERFACE("c8263aac-9e0c-4a2d-9b8e-007521a3317c") IDMLObject : IUnknown
                        // ----------------------------------------------------------
                        // ENUMG(6F8C2442-2BFB-4180-9EE5-EA1FB47AE35C)  COPPEventBlockReason
                        // ----------------------------------------------------------------
                        // template <>
                        // struct __declspec(uuid("0d82bd8d-fe62-5d67-a7b9-7886dd75bc4e"))
                        // IVector<ABI::Windows::Foundation::Uri*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Foundation::Uri*, ABI::Windows::Foundation::IUriRuntimeClass*>>
                        // ----------------------------------------------------------------
                        // class __declspec(uuid("f1bc4f8c-6bf8-42c0-b745-4fbe1a67e5a7"))
                        // IUriKey : public IHttpCacheKey
                        // ----------------------------------------------------------------
                        // class
                        // __declspec(uuid("3402945E-D19A-11d2-B35E-00104BC97924"))
                        // POLARITY CInstance
                        // ----------------------------------------------------------------
                        // struct __declspec(uuid("E234F2E2-BD69-4F8C-B3F2-7CD79ED466BD")) IKsDeviceFunctions;
                        else if (s_Line.StartsWith("MIDL_INTERFACE")   ||
                                 s_Line.StartsWith("ENUMG")            ||
                                 s_Line.Contains  ("DECLSPEC_UUID")    ||
                                 s_Line.Contains  ("__declspec(uuid(") ||
                                 s_Line.StartsWith("interface DX_DECLARE_INTERFACE")     || // d2d1.h
                                 s_Line.StartsWith("interface DWRITE_DECLARE_INTERFACE") || // dwrite.h
                                 s_Line.StartsWith("interface DML_DECLARE_INTERFACE"))      // DirectML.h
                        {
                            int s32_Start = i_Match.Index + s_GUID.Length;
                            String s_Name = ExtractNextWord(s_Lines, ref L, ref s32_Start);
                            if (s_Name.Length > 0)
                            {
                                String s_Namespace = FindNamespace(s_Lines, s32_FirstLine);
                                String s_FullName  = s_Namespace + s_Name;

                                AddInterface(s_GUID, s_FullName, i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // DECLARE_INTERFACE_IID_(ICompositorInterop, IUnknown, "25297D5C-3AD4-4C9C-B5CF-E36A38512330")
                        // ----------------------------------------------------------------
                        // IMMPID_START_LIST(MP,0x1000,"13384CF0-B3C4-11d1-AA92-00AA006BC80B")
                        // ----------------------------------------------------------------
                        // IMMPID_START_LIST(RP,0x2000,"79E82048-D320-11d1-9FF4-00C04FA37348")
                        else if (s_Line.StartsWith("DECLARE_INTERFACE_IID_") || // BEFORE "DECLARE_INTERFACE_IID" !
                                 s_Line.StartsWith("IMMPID_START_LIST"))
                        {
                            String[] s_Parts = ExtractBetweenParenthesis(s_Lines, ref L, 3);
                            if (s_Parts != null)
                            {
                                AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // DECLARE_INTERFACE_IID(IFileViewerA, "000214f0-0000-0000-c000-000000000046")
                        // ----------------------------------------------------------
                        // CROSS_PLATFORM_UUIDOF(IDxcBlob,     "8BA5FB08-5195-40e2-AC58-0D989C3A0102")
                        else if (s_Line.StartsWith("DECLARE_INTERFACE_IID") || // AFTER "DECLARE_INTERFACE_IID_" !
                                 s_Line.StartsWith("CROSS_PLATFORM_UUIDOF"))
                        {
                            String[] s_Parts = ExtractBetweenParenthesis(s_Lines, ref L, 2);
                            if (s_Parts != null)
                            {
                                AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // DEFINE_GUIDSTRUCT("9F2F7B66-65AC-4FA6-8AE4-123C78B89313", DEVINTERFACE_AUDIOENDPOINTPLUGIN);          
                        else if (s_Line.StartsWith("DEFINE_GUIDSTRUCT"))
                        {
                            String[] s_Parts = ExtractBetweenParenthesis(s_Lines, ref L, 2);
                            if (s_Parts != null)
                            {
                                AddInterface(s_GUID, s_Parts[1], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // DEFINE_CODECAPI_GUID( AVEncCommonFormatConstraint, "57cbb9b8-116f-4951-b40c-c2a035ed8f17", 0x57cbb9b8, 0x116f, 0x4951, 0xb4, 0x0c, 0xc2, 0xa0, 0x35, 0xed, 0x8f, 0x17 )
                        else if (s_Line.StartsWith("DEFINE_CODECAPI_GUID")) // codecapi.h
                        {
                            String[] s_Parts = ExtractBetweenParenthesis(s_Lines, ref L, 13);
                            if (s_Parts != null)
                            {
                                AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // const BSTR SpeechAudioFormatGUIDWave	= L"{C31ADBAE-527F-4ff5-A230-F62BB61FF70C}";
                        else if (s_Line.StartsWith("const BSTR "))
                        {
                            s_Line = s_Line.Substring(10);
                            String[] s_Parts = s_Line.Split('=');
                            if (s_Parts.Length == 2)
                            {
                                AddInterface(s_GUID, s_Parts[0], i_Interfaces, i_Guids, i_Ambiguous);
                                continue;
                            }
                        }

                        // DECLARE_EVENTGUID_STRING( g_szGuidSmtpSourceType, "{fb65c4dc-e468-11d1-aa67-00c04fa345f6}");
                        // DEFINE_GUID(GUID_SMTP_SOURCE_TYPE, 0xfb65c4dc, 0xe468, 0x11d1, 0xaa, 0x67, 0x0, 0xc0, 0x4f, 0xa3, 0x45, 0xf6);
                        else if (s_Line.StartsWith("DECLARE_EVENTGUID_STRING"))
                        {
                            // This can be ignored because a DEFINE_GUID() follows
                            continue;
                        }

                        Console.WriteLine("Syntax Error in line " + (s32_FirstLine +1) + " in " + s_FileName);
                    }
                }
            }

            // Add undocumented interfaces
            AddInterface("343BAA78-E34F-466C-9FFA-81AF5CE4CD34", "ABI.Windows.Internal.Security.SmartScreen.IAppReputationServiceFactory", i_Interfaces, i_Guids, i_Ambiguous);
            AddInterface("3EAD2336-B073-456F-BCAF-82587EB63487", "ABI.Windows.UI.Xaml.Hosting.IXamlIslandFactory",                         i_Interfaces, i_Guids, i_Ambiguous);
            AddInterface("DE27A01F-B561-4531-A278-FD012679EF1E", "ABI.Windows.Internal.Holographic.UI.IHolographicViewPropertiesFactory",  i_Interfaces, i_Guids, i_Ambiguous);

            Console.WriteLine("\n" +i_Interfaces.Count+ " interfaces found in "+s32_FileCount+" files.\n");
            WriteInterfaces(i_Interfaces, i_Ambiguous, SDK_BUILD);
        }

        // --------------------------------------------------------------------------

        /// <summary>
        /// remove multi-line comments 
        /// and
        /// remove inline comments
        /// typedef /* [uuid][public] */  DECLSPEC_UUID("54D8B4B9-663B-4a9c-95F6-0E749ABD70F1") __int64 ADO_LONGPTR;
        /// This function does not remove empty lines for displaying the correct line number in case of an error.
        /// </summary>
        static void PreProcessLines(ref String[] s_Lines)
        {
            bool b_MultiComment = false;
            for (int L=0; L<s_Lines.Length; L++)
            {
                String s_Line = s_Lines[L].Trim();

                // #define TRUSTEE_ACCESS_READ_WRITE (TRUSTEE_ACCESS_READ |       \
                //                                    TRUSTEE_ACCESS_WRITE)
                // is joined to:
                // #define TRUSTEE_ACCESS_READ_WRITE (TRUSTEE_ACCESS_READ | TRUSTEE_ACCESS_WRITE)
                if (s_Line.EndsWith("\\"))
                {
                    s_Lines[L]   = "";
                    s_Lines[L+1] = s_Line.TrimEnd('\\').Trim() + " " + s_Lines[L+1].Trim();
                    continue;
                }

                // Line may contain both comments:  "//* Copyright (c)" --> FIRST remove // then /*
                int s32_Begin = s_Line.IndexOf("//");
                if (s32_Begin >= 0)
                    s_Line = s_Line.Substring(0, s32_Begin);

                while (true)
                {
                    int s32_Start = b_MultiComment ? 0 : s_Line.IndexOf("/*");
                    if (s32_Start < 0)
                        break;
                    
                    int s32_End = s_Line.IndexOf("*/", s32_Start);
                    if (s32_End < 0)
                    {
                        b_MultiComment = true;
                        s_Line = s_Line.Substring(0, s32_Start).Trim();
                        break;
                    }
                    else
                    {
                        b_MultiComment = false;
                        s_Line = s_Line.Remove(s32_Start, s32_End + 2 - s32_Start).Trim();
                        continue; // Check if there are more comments in the same line
                    }
                }

                // struct __declspec(uuid("1adaa23a-eb67-41f3-aad8-5d984e9bacd4")) __declspec(novtable) 
                // ILearningModelOperatorProviderNative : IUnknown  
                s_Line = s_Line.Replace("__declspec(novtable)", "");

                // interface DECLSPEC_UUID("a27003cf-2354-4f2a-8d6a-ab7cff15437e") DECLSPEC_NOVTABLE
                // IRtwqAsyncCallback : public IUnknown
                s_Line = s_Line.Replace("DECLSPEC_NOVTABLE", "");

                // Replace multiple spaces with one space
                s_Line = Regex.Replace(s_Line, "\\s+", " ");

                s_Lines[L] = s_Line;

                Debug.Assert(!s_Line.Contains("//"));
                Debug.Assert(!s_Line.Contains("/*"));
                Debug.Assert(!s_Line.Contains("*/"));
            }

            Debug.Assert(!b_MultiComment);
        }

        // --------------------------------------------------------------------------

        // DECLARE_INTERFACE_IID_(ICompositorInterop, IUnknown, "25297D5C-3AD4-4C9C-B5CF-E36A38512330")
        static String[] ExtractBetweenParenthesis(String[] s_Lines, ref int L, int s32_ExpectedParts)
        {
            String s_Parenth = ExtractBetween(s_Lines, ref L, "(", ")");
            if (s_Parenth == null)
                return null;

            String[] s_Parts = s_Parenth.Split(',');
            if (s_Parts.Length != s32_ExpectedParts)
                return null;

            return s_Parts;
        }

        static String ExtractBetween(String[] s_Lines, ref int L, String s_Start, String s_End)
        {
            String s_Concat = s_Lines[L];
            do
            {
                String s_Next = GetNextValidLine(s_Lines, ref L);
                if (s_Next == null)
                    break;

                s_Concat += s_Next;
            }
            while (!s_Concat.Contains(s_Start) || !s_Concat.Contains(s_End));

            int s32_Start = s_Concat.IndexOf(s_Start);
            s32_Start += s_Start.Length;

            int s32_End = s_Concat.IndexOf(s_End, s32_Start);

            return s_Concat.Substring(s32_Start, s32_End - s32_Start);
        }

        /// <summary>
        /// Extract hex GUID which may span over multiple lines:
        /// { 0x76f5573e, 0xf13a, 0x40f5, 
        /// { 0xb2, 0x97, 0x81, 0xce, 0x9e, 0x18, 0x93, 0x3f } 
        /// };
        /// </summary>
        static String ExtractHexGuidMultiLine(String[] s_Lines, ref int L)
        {
            String s_Concat = "";
            do
            {
                String s_Line = s_Lines[L++];
                if (IsLineValid(s_Line, true))
                    s_Concat += s_Line;
            }
            while (CountChars(s_Concat, '}') < 2);

            return ExtractHexGuidInline(s_Concat);
        }

        static String ExtractHexGuidInline(String s_Line)
        {
            s_Line = s_Line.Replace(" ", "");

            int s32_Start = s_Line.IndexOf('{');
            if (s32_Start < 0)
                return null;

            int s32_End = s_Line.IndexOf("}}");
            if (s32_End < 0)
                return null;

            s_Line = s_Line.Substring(s32_Start, s32_End - s32_Start);
            s_Line = s_Line.Replace("{", "");

            return HexListToGuid(s_Line.Split(','));
        }

        /// <summary>
        /// Convert 
        /// "0x00f5573e", "0xf13a", "0x40f5", "0xb2", "0x97", "0x81", "0xce", "0x9e", "0x18", "0x93", "0x3f"
        /// or
        /// "0xf5573e", "0xf13a", "0x40f5", "0xb2", "0x97", "0x81", "0xce", "0x9e", "0x18", "0x93", "0x3f"
        /// into "00f5573e-f13a-40f5-b297-81ce9e18933f"
        /// -----------------------------------------------------------
        /// "DEFINE_GUID(GUID_NULL, 0L, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);"
        /// "DEFINE_GUID(KSDATAFORMAT_SUBTYPE_MIDI, 0x1D262760L, 0xE957, 0x11CF, 0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00);"
        /// </summary>
        static String HexListToGuid(String[] s_Parts, int s32_FirstPart = 0)
        {
            if (s_Parts.Length != 11 + s32_FirstPart)
                return null;

            UInt32[] u32_Num = new UInt32[11];
            for (int P=0; P<11; P++)
            {
                String s_Part = s_Parts[P + s32_FirstPart].Trim().ToUpper().TrimEnd('L');

                if (s_Part.StartsWith("0X"))
                {
                    if (!UInt32.TryParse(s_Part.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out u32_Num[P]))
                        return null;    
                }
                else
                {
                    if (!UInt32.TryParse(s_Part, out u32_Num[P]))
                        return null;    
                }
            }

            return String.Format("{0:X8}-{1:X4}-{2:X4}-{3:X2}{4:X2}-{5:X2}{6:X2}{7:X2}{8:X2}{9:X2}{10:X2}",
                   u32_Num[0],u32_Num[1],u32_Num[2],u32_Num[3],u32_Num[4],u32_Num[5],u32_Num[6],u32_Num[7],u32_Num[8],u32_Num[9],u32_Num[10]);
        }

        static int CountChars(String s_String, Char c_Find)
        {
            int s32_Count = 0;
            foreach(Char c_Char in s_String)
            {
                if (c_Char == c_Find)
                    s32_Count ++;
            }
            return s32_Count;
        }

        /// <summary>
        /// Searches the next word after the GUID
        /// This may be in the same line or in the next valid line:
        /// struct __declspec(uuid("E234F2E2-BD69-4F8C-B3F2-7CD79ED466BD")) IKsDeviceFunctions;
        /// or
        /// struct __declspec(uuid("0d82bd8d-fe62-5d67-a7b9-7886dd75bc4e"))
        /// IVector<ABI::Windows::Foundation::Uri*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Foundation::Uri*, ABI::Windows::Foundation::IUriRuntimeClass*>>
        /// </summary>
        static String ExtractNextWord(String[] s_Lines, ref int L, ref int s32_Pos)
        {
            String s_Line = s_Lines[L];
            StringBuilder i_Interface = new StringBuilder();

            bool b_AngleOpen = false;
            for (; true; s32_Pos++)
            {
                if (s32_Pos >= s_Line.Length)
                {
                    if (i_Interface.Length > 0)
                        break;

                    s32_Pos=0;
                    s_Line = GetNextValidLine(s_Lines, ref L);
                    if (s_Line == null)
                        break;

                    s_Line = s_Line.Replace("::", ".");
                }

                Char c_Char = s_Line[s32_Pos];
                if (c_Char == '<') b_AngleOpen = true;
                if (c_Char == '>') b_AngleOpen = false;

                if (b_AngleOpen || Char.IsLetter(c_Char) || Char.IsDigit(c_Char) || "_<.>*".IndexOf(c_Char) >= 0)
                {
                    i_Interface.Append(c_Char);
                }
                else
                {
                    if (i_Interface.Length > 0)
                        break;
                }
            }

            String s_Name = i_Interface.ToString();

            // struct __declspec(uuid("40556131-a2a1-5fab-aaee-5f35268ca26b"))
            // IIterator<::byte> : IIterator_impl<::byte>
            s_Name = s_Name.Replace("<.", "<");

            // typedef interface DECLSPEC_UUID("d1069067-2a65-4bf0-ae97-76184b67856b")
            // IDebugAdvanced4* PDEBUG_ADVANCED4;
            s_Name = s_Name.TrimEnd('*');

            // remove ambiguity between IKeyValuePair<HSTRING,IInspectable*> 
            // and                      IKeyValuePair<HSTRING, IInspectable*>
            s_Name = s_Name.Replace(",", ", ");
            s_Name = Regex .Replace(s_Name, "\\s+", " ");
            
            return s_Name;
        }

        static String GetNextValidLine(String[] s_Lines, ref int L)
        {
            for (int N=0; true; N++)
            {
                L ++;
                if (L >= s_Lines.Length || N > 6)
                    return null;

                String s_Line = s_Lines[L];
                if (IsLineValid(s_Line))
                    return s_Line;
            }
        }

        static String GetPreviousValidLine(String[] s_Lines, ref int L)
        {
            for (int N=0; true; N++)
            {
                L --;
                if (L < 0 || N > 6)
                    return null;

                String s_Line = s_Lines[L];
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
        static bool IsLineValid(String s_Line, bool b_AllowBraces = false)
        {
            // s_Line is already trimmed
            if (s_Line.Length == 0             ||
                s_Line.StartsWith("#if ")      || 
                s_Line.StartsWith("#endif")    || 
                s_Line.StartsWith("#define ")  || 
                s_Line.StartsWith("DEPRECATED"))
                return false;

            if (!b_AllowBraces)
            {
                if (s_Line.StartsWith("{")  || 
                    s_Line.StartsWith("}"))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// namespace ABI {
        ///    namespace Windows {
        ///       namespace UI {
        ///          namespace WebUI {
        ///             MIDL_INTERFACE("2b09a173-b68e-4def-88c1-8de84e5aab2f")
        /// --------------- OR ----------------
        /// namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
        /// template <>
        /// struct __declspec(uuid("cdb5efb3-5788-509d-9be1-71ccb8a3362a"))
        /// IAsyncOperation<bool> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>>
        /// </summary>
        static String FindNamespace(String[] s_Lines, int L) // not ref !
        {
            String s_Return = "";
            for (int i=0; i<8; i++) // search max 8 lines backwards
            {
                String s_Line = GetPreviousValidLine(s_Lines, ref L);
                if (s_Line == null)
                    break;

                while (true)
                {
                    int s32_Found = s_Line.LastIndexOf("namespace");
                    if (s32_Found < 0)
                        break;

                    String s_Namespace = s_Line.Substring(s32_Found + 9).Trim(' ', '{');
                    s_Line = s_Line.Substring(0, s32_Found);

                    s_Return = s_Namespace + "." + s_Return;
                    if (s_Namespace == "ABI")
                        return s_Return;
                }
            }
            return "";
        }

        static bool AddInterface(String s_GUID, String s_Name, 
                                 SortedList<String, String> i_Interfaces, 
                                 SortedList<String, String> i_Guids, 
                                 Dictionary<String, String> i_Ambiguous)
        {
            s_GUID = s_GUID.Trim('"', ' ', '{', '}');
            s_Name = s_Name.Trim('"', ' ');

            if (s_GUID.Length != 36 || s_GUID[8] != '-' || s_GUID[13] != '-' || s_GUID[18] != '-' || s_GUID[23] != '-')
            {
                Console.WriteLine("Invalid GUID: " + s_GUID);
                return false;
            }

            if (s_Name.Length < 2 || s_Name == "struct" || s_Name == "class" || s_Name == "enum" || s_Name == "null" || 
                                     s_Name == "DWORD" || s_Name == "__int64" || s_Name == "long" || s_Name == "__declspec")
            {
                Console.WriteLine("Invalid Name: '" + s_Name + "' for " + s_GUID);
                return false;
            }

            // Microsoft has declared multiple ambiguous interfaces --> warning
            String s_ExistName;
            if (i_Guids.TryGetValue(s_GUID, out s_ExistName))
            {
                String s_NameI      = Insert_I(s_Name);
                String s_ExistNameI = Insert_I(s_ExistName);

                // Same interface defined as KSMFT_CATEGORY_AUDIO_ENCODER and MFT_CATEGORY_AUDIO_ENCODER
                // Same interface defined as ScriptingContext and CLSID_ScriptingContext
                if (s_ExistName.Contains(s_Name) || 
                    s_ExistName.Contains(s_NameI))
                {
                    // store the longer name (s_ExistName)
                    s_Name = s_ExistName;
                }
                else if (s_Name.Contains(s_ExistName) || 
                         s_Name.Contains(s_ExistNameI))
                {
                    // store the longer name (s_Name)
                }
                else
                {
                    String s_Ambig;
                    if (!i_Ambiguous.TryGetValue(s_GUID, out s_Ambig)) s_Ambig = "";

                    if (!s_Ambig.Contains(s_Name))      s_Ambig += "\t" + s_Name;
                    if (!s_Ambig.Contains(s_ExistName)) s_Ambig += "\t" + s_ExistName;
                    i_Ambiguous[s_GUID] = s_Ambig.Trim();
                }
            }
            i_Guids[s_GUID] = s_Name;

            // ------------------------------------

            // --> concat multiple GUID's for the same interface name with a tab character.
            String s_ExistGuid;
            if (i_Interfaces.TryGetValue(s_Name, out s_ExistGuid))
            {
                if (s_ExistGuid.Contains(s_GUID))
                    return true;

                s_GUID += '\t' + s_ExistGuid;
            }
            i_Interfaces[s_Name] = s_GUID;
            return true;
        }

        /// <summary>
        /// Avoid error for "ABI.Windows.Foundation.AsyncActionCompletedHandler" 
        ///             and "ABI.Windows.Foundation.IAsyncActionCompletedHandler"
        /// by inserting an "I" as first character of the interface name.
        ///         
        /// But do not modify "DateTime" in angle backets:
        /// "ABI.Windows.Foundation.IReference<struct ABI.Windows.Foundation.DateTime>"
        /// Attention: 
        /// The interface name may already start with 'I': IdleDispatchedHandler / IIdleDispatchedHandler
        /// </summary>
        static String Insert_I(String s_Interface)
        {
            int s32_Angle = s_Interface.IndexOf('<');
            if (s32_Angle < 0)
                s32_Angle = s_Interface.Length -1;

            int s32_LastDot = s_Interface.LastIndexOf('.', s32_Angle);
            if (s32_LastDot > 0)
                return s_Interface.Insert(s32_LastDot + 1, "I");

            return s_Interface;
        }

        // =========================================================================================

        /// <summary>
        /// Write an INI and a HTML file
        /// </summary>
        static void WriteInterfaces(SortedList<String, String> i_Interfaces, Dictionary<String, String> i_Ambiguous, int s32_Build)
        {
            if (i_Interfaces.Count == 0)
                return;

            String s_WinVer  = GetWindowsVersion(s32_Build);
            String s_Name    = ONLY_WINRT ? "WinRT Interfaces" : "All Interfaces";
            String s_Title   = s_Name + " - Windows GUID Database";
            String s_Comment = String.Format("{0} interfaces automatically extracted from the {1} SDK header files (https://github.com/Elmue/WindowsRT-GUID-Analyzer)",
                                             i_Interfaces.Count, s_WinVer);

            StringBuilder i_Ini = new StringBuilder();
            StringBuilder i_Xml = new StringBuilder();
            StringBuilder i_Htm = new StringBuilder();
            StringBuilder i_Cpp = new StringBuilder();
            StringBuilder i_CS  = new StringBuilder();

            i_Ini.Append("[All Interfaces]\r\n");

            i_Htm.Append("<div>&nbsp;</div>\r\n");
            i_Htm.Append("<table border='1' cellspacing='0' cellpadding='0'>\r\n");

            foreach (KeyValuePair<String, String> i_Pair in i_Interfaces)
            { 
                foreach (String s_GUID in i_Pair.Value.Split('\t'))
                {
                    String s_XmlWarn = "";
                    String s_Ambig;
                    if (i_Ambiguous.TryGetValue(s_GUID, out s_Ambig))
                    {
                        s_Ambig = s_Ambig.Replace("\t", " and ");

                        i_Htm.AppendFormat("\t<tr><td colspan='2' class='Warning'>The following GUID is ambiguous for {0}</td></tr>\r\n", Amp(s_Ambig));
                        i_Ini.AppendFormat("\r\n; The following GUID is ambiguous for {0}\r\n",                  s_Ambig);
                    //  i_Cpp.AppendFormat("\r\n\t\t// The following GUID is ambiguous for {0}\r\n",             s_Ambig); 
                        i_CS .AppendFormat("\r\n\t\t// The following GUID is ambiguous for {0}\r\n",             s_Ambig);
                        s_XmlWarn = String.Format("\r\n\t           Warning=\"This GUID is ambiguous for {0}\"", Amp(s_Ambig));
                    }

                    i_Ini.AppendFormat("{0} = {1}\r\n",                                    s_GUID, i_Pair.Key);
                    i_Xml.AppendFormat("\t<Interface GUID=\"{0}\" Name=\"{1}\"{2} />\r\n", s_GUID, Amp(i_Pair.Key), s_XmlWarn);
                    i_Htm.AppendFormat("\t<tr><td>{0}</td><td>{1}</td></tr>\r\n",          s_GUID, Amp(i_Pair.Key));
                //  i_Cpp.AppendFormat("\t\tInterfaces().SetAt(L\"{0}\", L\"{1}\");\r\n",  s_GUID, i_Pair.Key);
                    i_CS .AppendFormat("\t\tmi_Interfaces[\"{0}\"] = \"{1}\";\r\n",        s_GUID, i_Pair.Key);
                }
            }

            i_Htm.Append("</table>\r\n");

            SaveTemplate(".ini", s_WinVer, i_Ini, s_Name, s_Title, s_Comment);
            SaveTemplate(".xml", s_WinVer, i_Xml, s_Name, s_Title, s_Comment);
            SaveTemplate(".htm", s_WinVer, i_Htm, s_Name, s_Title, s_Comment);
            SaveTemplate(".h",   s_WinVer, i_Cpp, s_Name, s_Title, s_Comment);
            SaveTemplate(".cs",  s_WinVer, i_CS , s_Name, s_Title, s_Comment);
        }

        static String Amp(String s_Name)
        {
            return s_Name.Replace("<", "&lt;").Replace(">", "&gt;");
        }

        /// <summary>
        /// Write an INI and a HTML file
        /// </summary>
        static void WriteActivationDlls(SortedList<String, List<String>> i_Dlls, int s32_TotCount, int s32_Build)
        {
            String s_WinVer  = GetWindowsVersion(s32_Build);
            String s_Title   = "WinRT Activatable Classes";
            String s_Comment = String.Format("{0} Activatable Classes automatically extracted from the {1} Registry (https://github.com/Elmue/WindowsRT-GUID-Analyzer)",
                                             s32_TotCount, s_WinVer);

            StringBuilder i_Ini = new StringBuilder();
            StringBuilder i_Xml = new StringBuilder();
            StringBuilder i_Htm = new StringBuilder();

            foreach (KeyValuePair<String, List<String>> i_Pair in i_Dlls)
            {
                i_Ini.AppendFormat("\r\n[{0}]\r\n",            i_Pair.Key);
                i_Xml.AppendFormat("\t<DLL Path=\"{0}\">\r\n", i_Pair.Key);
                i_Htm.AppendFormat("<h4>{0}</h4>\r\n",         i_Pair.Key);
                i_Htm.Append("<table border='1' cellspacing='0' cellpadding='0'>\r\n");

                i_Pair.Value.Sort();
                for (int C=0; C<i_Pair.Value.Count; C++)
                {
                    String s_Class = i_Pair.Value[C];
                    i_Ini.AppendFormat("Class_{0} = {1}\r\n",                     C+1, s_Class);
                    i_Xml.AppendFormat("\t\t<Class Name=\"{0}\" />\r\n",               s_Class);
                    i_Htm.AppendFormat("\t<tr><td>{0}</td><td>{1}</td></tr>\r\n", C+1, s_Class);
                }

                i_Xml.Append("\t</DLL>\r\n");
                i_Htm.Append("</table>\r\n");
            }

            SaveTemplate(".ini", s_WinVer, i_Ini, s_Title, s_Title, s_Comment);
            SaveTemplate(".xml", s_WinVer, i_Xml, s_Title, s_Title, s_Comment);
            SaveTemplate(".htm", s_WinVer, i_Htm, s_Title, s_Title, s_Comment);
        }

        // =========================================================================================

        static String GetWindowsVersion(int s32_Build)
        {
            String s_Ver = "8";
                 if (s32_Build >= 22000) s_Ver = "11";
            else if (s32_Build >= 10000) s_Ver = "10";
            return String.Format("Windows {0} (Build {1})", s_Ver, s32_Build);
        }

        static String LoadResourceString(String s_Resource)
		{
			Assembly i_Ass  = Assembly.GetExecutingAssembly();
			Stream   i_Strm = i_Ass.GetManifestResourceStream("GuidAnalyzer.Resources." + s_Resource);
            if (i_Strm == null)
                throw new Exception("Resource not found: "+s_Resource);

			StreamReader i_Read = new StreamReader(i_Strm, true);
			return i_Read.ReadToEnd();
		}

        static void SaveTemplate(String s_FileExt, String s_WinVer, StringBuilder i_Builder, String s_Name, String s_Title, String s_Comment)
        {
            String s_Template = LoadResourceString("Template" + s_FileExt);
            String s_Text     = String.Format(s_Template, s_Title, s_Comment, i_Builder.ToString().TrimEnd());
            String s_Path     = OUT_PATH + s_WinVer + " " + s_Name + s_FileExt;
            File.WriteAllText(s_Path, s_Text, Encoding.UTF8);
            Console.WriteLine("File saved: " + s_Path);
        }
    }
}
