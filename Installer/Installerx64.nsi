
;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"
  !include "X64.nsh"
  !include "WinVer.nsh"


;--------------------------------
;General

  ;Name and file
  Name "EID Authentication"
  OutFile "EIDInstallx64.exe"

  ;Default installation folder
  InstallDir "$SYSDIR"
  

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_INSTFILES
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH
  !insertmacro MUI_UNPAGE_FINISH
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"
  !insertmacro MUI_LANGUAGE "French"


;--------------------------------
;Installer Sections

Section "Core" SecCore
  SectionIn RO

  SetOutPath "$INSTDIR"
  
  ;Create uninstaller
  WriteUninstaller "$SYSDIR\EIDUninstall.exe"

  ;Uninstall info
  SetRegView 64

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "DisplayName" "EID Authentication"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "UninstallString" "$WINDIR\SYSWOW64\EIDUninstall.exe"

  ;ADD YOUR OWN FILES HERE...

  ${DisableX64FSRedirection}
  FILE "..\x64\Release\EIDAuthenticationPackage.dll"
  FILE "..\x64\Release\EIDCredentialProvider.dll"
  FILE "..\x64\Release\EIDPasswordChangeNotification.dll"
  FILE "..\x64\Release\EIDConfigurationWizard.exe"

  ExecWait 'rundll32.exe EIDAuthenticationPackage.dll,DllRegister'
 
 
  SetPluginUnload manual

  SetRebootFlag true

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Core"
  LangString DESC_SecCore ${LANG_FRENCH} "Core"

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"


  Delete /REBOOTOK "$SYSDIR\EIDUninstall.exe"
  SetRegView 64
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"

  ${DisableX64FSRedirection}
  ExecWait 'rundll32.exe EIDAuthenticationPackage.dll,DllUnRegister'

  Delete /REBOOTOK "$SYSDIR\EIDAuthenticationPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"
  Delete /REBOOTOK "$SYSDIR\EIDConfigurationWizard.exe"


  SetPluginUnload manual
  SetRebootFlag true

SectionEnd


Function .onInit
  ${If} ${RunningX64}
  ${Else}
    MessageBox MB_OK "This installer is designed for 64bits only"
    Abort
  ${EndIf}

  ${If} ${AtMostWinXP}
    MessageBox MB_OK "This installer is designed for Windows Vista or older"
    Abort
  ${EndIf}


  ${DisableX64FSRedirection}
  IfFileExists "$SYSDIR\EIDAuthenticationPackage.dll" CheckInstallNotOk CheckInstallEnd
  CheckInstallNotOk:
    MessageBox MB_OK "Please uninstall first !"
    Abort
 
  CheckInstallEnd:
  ${EnableX64FSRedirection}
FunctionEnd