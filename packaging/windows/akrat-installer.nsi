Unicode true

!ifndef AKRAT_VERSION
  !define AKRAT_VERSION "0.0.0"
!endif

!include "MUI2.nsh"

Name "AKRAT ${AKRAT_VERSION}"
OutFile "..\..\dist\AKRAT-Setup-v${AKRAT_VERSION}.exe"
InstallDir "$LOCALAPPDATA\Programs\AKRAT"
InstallDirRegKey HKCU "Software\AKRAT" "InstallDir"
RequestExecutionLevel user
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${AKRAT_VERSION}.0"
VIAddVersionKey "ProductName" "AKRAT"
VIAddVersionKey "ProductVersion" "${AKRAT_VERSION}"
VIAddVersionKey "FileVersion" "${AKRAT_VERSION}"
VIAddVersionKey "FileDescription" "Installateur AKRAT"
VIAddVersionKey "CompanyName" "AKRAT"
VIAddVersionKey "LegalCopyright" "Copyright AKRAT"

!define MUI_ABORTWARNING
!define MUI_ICON "akrat.ico"
!define MUI_UNICON "akrat.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\akrat-desktop.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Lancer AKRAT maintenant"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "French"

Function .onInit
  SetShellVarContext current
FunctionEnd

Function un.onInit
  SetShellVarContext current
FunctionEnd

Section "AKRAT" SEC_AKRAT
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "..\..\target\release\akrat-desktop.exe"
  File "..\..\target\release\akrat.exe"
  File "akrat.ico"

  CreateDirectory "$SMPROGRAMS\AKRAT"
  CreateShortcut "$SMPROGRAMS\AKRAT\AKRAT.lnk" "$INSTDIR\akrat-desktop.exe" "" "$INSTDIR\akrat.ico" 0 SW_SHOWNORMAL "" "AKRAT — Messagerie P2P sécurisée"

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\AKRAT" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "DisplayName" "AKRAT"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "DisplayVersion" "${AKRAT_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "Publisher" "AKRAT"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "DisplayIcon" "$INSTDIR\akrat.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT" "NoRepair" 1
SectionEnd

Section "Raccourci sur le Bureau" SEC_DESKTOP
  CreateShortcut "$DESKTOP\AKRAT.lnk" "$INSTDIR\akrat-desktop.exe" "" "$INSTDIR\akrat.ico" 0 SW_SHOWNORMAL "" "AKRAT — Messagerie P2P sécurisée"
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\AKRAT.lnk"
  Delete "$SMPROGRAMS\AKRAT\AKRAT.lnk"
  RMDir "$SMPROGRAMS\AKRAT"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AKRAT"
  DeleteRegKey HKCU "Software\AKRAT"
  RMDir /r "$INSTDIR"
SectionEnd
