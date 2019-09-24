
;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"
  !include "X64.nsh"
  !include "WinVer.nsh"

;--------------------------------
;General

  ;Name and file
  Name "EID Authentication"
  OutFile "EIDInstall.exe"

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
  
  ;ADD YOUR OWN FILES HERE...
  FILE "..\Release\EIDAuthenticationPackage.dll"
  FILE "..\Release\EIDCredentialProvider.dll"
  FILE "..\Release\EIDPasswordChangeNotification.dll"
  FILE "..\Release\EIDConfigurationWizard.exe"

 
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\EIDUninstall.exe"

  ;Uninstall info
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "DisplayName" "EID Authentication"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "UninstallString" "$INSTDIR\EIDUninstall.exe"

  System::Call "EIDAuthenticationPackage.dll::DllRegister()"
 
 
  SetPluginUnload manual

  SetRebootFlag true

SectionEnd

Section /o "Belgium EID Patch" SecBeid

  System::Call "EIDAuthenticationPackage.dll::EIDPatch()"

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Core"
  LangString DESC_SecCore ${LANG_FRENCH} "Core"

  LangString DESC_SecBeid ${LANG_ENGLISH} "Insert missing configuration parameters required to use Belgium EID Card - the Belgium middleware must be installed !"
  LangString DESC_SecBeid ${LANG_FRENCH} "Insère des paramètres de configuration nécessaires pour l'utilisation de la carte d'identité belge - le middleware doit être installé !"

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecBeid} $(DESC_SecBeid)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"


  System::Call "EIDAuthenticationPackage.dll::DllUnRegister()"
  System::Call "EIDAuthenticationPackage.dll::EIDUnPatch()"

  Delete /REBOOTOK "$INSTDIR\EIDUninstall.exe"
  Delete /REBOOTOK "$INSTDIR\EIDAuthenticationPackage.dll"
  Delete /REBOOTOK "$INSTDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$INSTDIR\EIDPasswordChangeNotification.dll"
  Delete /REBOOTOK "$INSTDIR\EIDConfigurationWizard.exe"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"

  SetPluginUnload manual
  SetRebootFlag true

SectionEnd

Function .onInit

  ${If} ${RunningX64}
    MessageBox MB_OK "This installer is designed for 32bits only"
    Abort
  ${EndIf}

  ${If} ${AtMostWinXP}
    MessageBox MB_OK "This installer is designed for Windows Vista or older"
    Abort
  ${EndIf}

IfFileExists "$PROGRAMFILES\Belgium Identity Card\beid35libCpp.dll" CheckOk CheckEnd
CheckOk:
  ; This is what is done by sections.nsh SelectSection macro
   !insertmacro SelectSection ${SecBeid}

 
CheckEnd:

IfFileExists "$SYSDIR\EIDAuthenticationPackage.dll" CheckInstallNotOk CheckInstallEnd
CheckInstallNotOk:
  MessageBox MB_OK "Please uninstall first !"
  Abort
 
CheckInstallEnd:
FunctionEnd