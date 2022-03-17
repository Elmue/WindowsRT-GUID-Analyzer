This small tool has 2 functionalities:

1.) Extract all Windows RT Activitable Classes from the Windows Registry and find out in which DLL they are implemented

2.) Extract all interfaces that are defined in the header files of the Windows SDK in subfolder "Include\10.0.BuildNumber.0\winrt"

The results are saved:

a.) as HTML table

b.) as INI file which can easily be read by a C++ project

c.) as XML file which can easily be read by a C# project

You can also chose with variable ONLY_WINRT=false to extract ALL Windows COM interfaces, which results in 15000 interfaces.

Please go to the Release folder and see some of the already generated files.

To see them correctly use these links:

https://htmlpreview.github.io/?https://github.com/Elmue/WindowsRT-GUID-Analyzer/blob/main/Release/Windows%2011%20(Build%2022000)%20WinRT%20Interfaces.htm

https://htmlpreview.github.io/?https://github.com/Elmue/WindowsRT-GUID-Analyzer/blob/main/Release/Windows%2011%20(Build%2022000)%20WinRT%20Activatable%20Classes.htm

The main purpose is to get information about the Windows interfaces when you are analyzing a third party software.

With IInspectable->GetIids() you can get a lot of IIDs but finding which class they correspond to is very difficult.
