The Windows RT CLSIDs are no longer stored in the registry as formerly the COM interfaces under HKEY_CLASSES_ROOT\CLSID.
The purpose of this project is to get the interface name from a GUID when you are analyzing a third party software.
With IInspectable->GetIids() you can get a lot of IIDs but getting the information to which class the IID corresponds is not easy.

Now you can easily implement a Debug function into your code which displays interface names instead of cryptic GUID's.

This tool which has 2 functionalities:

1.) Extract all Windows RT Activitable Classes from the Windows Registry and find out in which DLL they are implemented

2.) Extract all interfaces that are defined in the header files of the Windows SDK in subfolder "Include\10.0.BuildNumber.0\winrt"

The results are saved:

a.) as HTML table

b.) as INI file

c.) as XML file

d.) as C# file which includes a function GetInterfaceName() which retuns the interface name by a given GUID

e.) as C++ file which includes a function GetInterfaceName() which retuns the interface name by a given GUID

You can also set variable ONLY_WINRT=false to extract ALL Windows COM interfaces, which results in 15000 interfaces.

Please go to the Release folder and see some of the already generated files.
To see them correctly use these links:

All 4100 Windows RT activatable classes (Windows 11):
https://htmlpreview.github.io/?https://github.com/Elmue/WindowsRT-GUID-Analyzer/blob/main/Release/Windows%2011%20(Build%2022000)%20WinRT%20Activatable%20Classes.htm

All 12400 Windows RT interfaces (Windows 11):
https://htmlpreview.github.io/?https://github.com/Elmue/WindowsRT-GUID-Analyzer/blob/main/Release/Windows%2011%20(Build%2022000)%20WinRT%20Interfaces.htm

All 25600 Windows interfaces (Windows 11):
https://htmlpreview.github.io/?https://github.com/Elmue/WindowsRT-GUID-Analyzer/blob/main/Release/Windows%2011%20(Build%2022000)%20All%20Interfaces.htm


