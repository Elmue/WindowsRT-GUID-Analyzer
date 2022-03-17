This small tool has 2 functionalities:

1.) Extract all Windows RT Activitable Classes from the Windows Registry and find out in which DLL they are implemented
2.) Extract all interfaces that are defined in the header files of the Windows SDK in subfolder "Include\10.0.BuildNumber.0\winrt"

The results are saved:

a.) as HTML table
b.) as INI file which can easily be read by a C++ project
c.) as XML file which can easily be read by a C# project

The main purpose is to get information about the Windows RT interfaces when you are analyzing a third party software.
With IInspectable->GetIids() you can get a lot of IIDs but finding which class they correspond to is very difficult.
