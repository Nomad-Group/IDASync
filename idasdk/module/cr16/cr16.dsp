# Microsoft Developer Studio Project File - Name="CR16" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=CR16 - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "CR16.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "CR16.mak" CFG="CR16 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "CR16 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "CR16 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "CR16 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CR16_EXPORTS" /YX /FD /c
# ADD CPP /nologo /Gz /MT /W3 /GX /O2 /I "../../include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CR16_EXPORTS" /D "__NT__" /D "__IDP__" /FR /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x419 /d "NDEBUG"
# ADD RSC /l 0x419 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ida.lib /nologo /dll /map /machine:I386 /out:"../../bin/w32/CR16.w32" /libpath:"../../libvc.w32" /export:LPH
# SUBTRACT LINK32 /pdb:none /debug
# Begin Special Build Tool
SOURCE=$(InputPath)
# End Special Build Tool

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /GX /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CR16_EXPORTS" /YX /FD /ZI /GZ /c
# ADD CPP /nologo /Gz /MTd /W3 /GX /Od /I "../../include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CR16_EXPORTS" /D "__NT__" /D "__IDP__" /FR /YX /FD /ZI /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x419 /d "_DEBUG"
# ADD RSC /l 0x419 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ida.lib /nologo /dll /debug /machine:I386 /out:"../../bin/w32/CR16.w32" /pdbtype:sept /libpath:"../../libvc.w32" /export:LPH
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
SOURCE=$(InputPath)
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "CR16 - Win32 Release"
# Name "CR16 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\ANA.CPP

!IF  "$(CFG)" == "CR16 - Win32 Release"

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# ADD CPP /Gz

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\EMU.CPP

!IF  "$(CFG)" == "CR16 - Win32 Release"

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# ADD CPP /Gz

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\INS.CPP

!IF  "$(CFG)" == "CR16 - Win32 Release"

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# ADD CPP /Gz

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\OUT.CPP

!IF  "$(CFG)" == "CR16 - Win32 Release"

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# ADD CPP /Gz

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\REG.CPP

!IF  "$(CFG)" == "CR16 - Win32 Release"

!ELSEIF  "$(CFG)" == "CR16 - Win32 Debug"

# ADD CPP /Gz

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
