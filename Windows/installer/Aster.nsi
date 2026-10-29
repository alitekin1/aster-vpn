Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!ifndef VERSION
 !error "VERSION is required"
!endif
!ifndef PAYLOAD
 !error "PAYLOAD is required"
!endif
Name "Aster"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\Aster"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 32
CRCCheck force
ManifestDPIAware true
Icon "${ICON}"
UninstallIcon "${ICON}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Aster contributors"
VIAddVersionKey /LANG=1033 "ProductName" "Aster"
VIAddVersionKey /LANG=1033 "FileDescription" "Aster Windows Setup"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
BrandingText "Aster — Your traffic. Your rules."
ShowInstDetails show
ShowUninstDetails show
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAster
!define MUI_FINISHPAGE_RUN_TEXT "Open Aster"
!define MUI_FINISHPAGE_TEXT "Aster is installed. Your existing servers and settings are preserved."
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Var UpdateMode
Var Params
Var SetupMutex

!macro StopAster PREFIX
Function ${PREFIX}StopAster
 retry:
  FindWindow $0 "webview" "Aster"
  StrCmp $0 0 done
  ; Older portable builds cannot quit through our installer protocol.
  System::Call 'user32::SendMessageTimeoutW(p r0, i 0x8030, p 0, p 0, i 2, i 1000, *p .r2) p .r3'
  IntCmp $2 0x41535452 canquit timedout timedout
 canquit:
  ; Aster 0.2+ handles this as graceful Quit, including packet/route cleanup.
  System::Call 'user32::PostMessageW(p r0, i 0x802f, p 0, p 0)'
  StrCpy $1 0
 wait:
  Sleep 100
  FindWindow $0 "webview" "Aster"
  StrCmp $0 0 done
  IntOp $1 $1 + 1
  IntCmp $1 300 timedout wait timedout
 timedout:
  IfSilent silentfail
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Please quit Aster from its system tray menu, then choose Retry. Your VPN must stop before updating or uninstalling." IDRETRY retry
 silentfail:
  SetErrorLevel 2
  Abort
 done:
  Sleep 250
FunctionEnd
!macroend
!insertmacro StopAster ""
!insertmacro StopAster "un."

Function .onInit
 !if "${ARCH}" == "ARM64"
  ${IfNot} ${IsNativeARM64}
    MessageBox MB_ICONSTOP "This installer requires ARM64 Windows. Download the x64 installer for Intel/AMD computers." /SD IDOK
    Abort
  ${EndIf}
 !else
  ${IfNot} ${IsNativeAMD64}
    MessageBox MB_ICONSTOP "This installer requires x64 Windows. Download the ARM64 installer for ARM computers." /SD IDOK
    Abort
  ${EndIf}
 !endif
 System::Call 'kernel32::CreateMutexW(p 0, i 0, w "Local\Aster.Windows.Setup") p .r0 ?e'
 StrCpy $SetupMutex $0
 Pop $1
 StrCmp $1 183 0 +3
  MessageBox MB_ICONSTOP "Another Aster installer is already running." /SD IDOK
  Abort
 SetRegView 64
 SetShellVarContext all
 ReadRegStr $0 HKLM "Software\Aster" "InstallLocation"
 StrCmp $0 "" +2
  StrCpy $INSTDIR $0
 ${GetParameters} $Params
 ClearErrors
 ${GetOptions} $Params "/UPDATE" $0
 ${IfNot} ${Errors}
  StrCpy $UpdateMode "1"
 ${EndIf}
 ClearErrors
 Call StopAster
FunctionEnd

Section "Aster" SEC_MAIN
 InitPluginsDir
 SetOutPath "$PLUGINSDIR"
 File /oname=Ensure-WebView2.ps1 "${WEBVIEW_SCRIPT}"
 File /oname=MicrosoftEdgeWebview2Setup.exe "${BOOTSTRAP}"
 DetailPrint "Checking Microsoft WebView2…"
 ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Ensure-WebView2.ps1"' $0
 StrCmp $0 0 webviewok
  MessageBox MB_ICONSTOP "Microsoft WebView2 could not be installed. Check your internet connection and run Aster Setup again." /SD IDOK
  SetErrorLevel 3
  Abort
 webviewok:
 ClearErrors
 SetOutPath "$INSTDIR"
 !include "${INSTALL_FILES}"
 IfErrors installfailed
 WriteUninstaller "$INSTDIR\Uninstall.exe"
 WriteRegStr HKLM "Software\Aster" "InstallLocation" "$INSTDIR"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "DisplayName" "Aster"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "DisplayVersion" "${VERSION}"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "Publisher" "Aster"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "InstallLocation" "$INSTDIR"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "DisplayIcon" "$INSTDIR\Aster.exe"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "NoModify" 1
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "NoRepair" 1
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster" "EstimatedSize" ${INSTALLED_KB}
 CreateDirectory "$SMPROGRAMS\Aster"
 CreateShortcut "$SMPROGRAMS\Aster\Aster.lnk" "$INSTDIR\Aster.exe"
 CreateShortcut "$SMPROGRAMS\Aster\Uninstall Aster.lnk" "$INSTDIR\Uninstall.exe"
 CreateShortcut "$DESKTOP\Aster.lnk" "$INSTDIR\Aster.exe"
 SetErrorLevel 0
 Goto installed
 installfailed:
  MessageBox MB_ICONSTOP "Aster could not be installed. Check disk space and whether another process is using its files, then run Setup again." /SD IDOK
  SetErrorLevel 4
  Abort
 installed:
SectionEnd

Function LaunchAster
 Exec '"$INSTDIR\Aster.exe"'
FunctionEnd
Function .onInstSuccess
 StrCmp $UpdateMode "1" 0 done
 Call LaunchAster
 done:
FunctionEnd

Function un.onInit
 SetRegView 64
 SetShellVarContext all
FunctionEnd
Section "Uninstall"
 Call un.StopAster
 !include "${UNINSTALL_FILES}"
 Delete "$INSTDIR\Uninstall.exe"
 Delete "$SMPROGRAMS\Aster\Aster.lnk"
 Delete "$SMPROGRAMS\Aster\Uninstall Aster.lnk"
 RMDir "$SMPROGRAMS\Aster"
 Delete "$DESKTOP\Aster.lnk"
 DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aster"
 DeleteRegKey HKLM "Software\Aster"
 RMDir "$INSTDIR"
 ; The per-user encrypted AppData store is deliberately retained.
SectionEnd
