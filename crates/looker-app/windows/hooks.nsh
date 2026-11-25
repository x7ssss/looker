!include "LogicLib.nsh"
!include "WinMessages.nsh"

!define LOOKER_HOOK_DIR "${__FILEDIR__}"

!macro _LookerSetPathScopeEnv
  !if "${INSTALLMODE}" == "perMachine"
    System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", t "HKLM")'
  !else if "${INSTALLMODE}" == "both"
    ${If} $MultiUser.InstallMode == "AllUsers"
      System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", t "HKLM")'
    ${Else}
      System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", t "HKCU")'
    ${EndIf}
  !else
    System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", t "HKCU")'
  !endif
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Bundle standalone looker CLI binary next to looker-app.exe in $INSTDIR
  File /a "/oname=looker.exe" "${LOOKER_HOOK_DIR}\..\..\..\target\release\looker.exe"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_TARGET", t "$INSTDIR")'
  !insertmacro _LookerSetPathScopeEnv

  ; Update PATH via PowerShell using DoNotExpandEnvironmentNames so >1024-char PATHs and %VARS% are preserved
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$$d = ($$env:LOOKER_PATH_TARGET).Trim().TrimEnd([char]92); if (-not $$d) { exit 0 }; $$lm = ($$env:LOOKER_PATH_SCOPE -eq 'HKLM'); $$r = if ($$lm) { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }; $$sk = if ($$lm) { 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' } else { 'Environment' }; $$k = $$r.OpenSubKey($$sk, $$true); if (-not $$k) { $$k = $$r.CreateSubKey($$sk, $$true) }; try { $$raw = $$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $$kind = try { $$k.GetValueKind('Path') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }; if ($$kind -ne [Microsoft.Win32.RegistryValueKind]::String -and $$kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) { $$kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }; $$parts = @(); if ($$raw) { $$parts = @($$raw -split ';' | Where-Object { $$_ -ne '' }) }; if (-not ($$parts | Where-Object { $$_.Trim().TrimEnd([char]92).Equals($$d, [System.StringComparison]::OrdinalIgnoreCase) })) { $$k.SetValue('Path', ((@($$parts) + @($$d)) -join ';'), $$kind) } } finally { $$k.Close() }"`
  Pop $0

  System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_TARGET", p 0)'
  System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", p 0)'

  ${If} $0 == 0
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
  ${Else}
    DetailPrint "Warning: Unable to add $INSTDIR to PATH automatically (exit code: $0)"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Remove bundled looker CLI before Tauri runs RMDir "$INSTDIR"
  Delete "$INSTDIR\looker.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_TARGET", t "$INSTDIR")'
    !insertmacro _LookerSetPathScopeEnv

    nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$$d = ($$env:LOOKER_PATH_TARGET).Trim().TrimEnd([char]92); if (-not $$d) { exit 0 }; $$lm = ($$env:LOOKER_PATH_SCOPE -eq 'HKLM'); $$r = if ($$lm) { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }; $$sk = if ($$lm) { 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' } else { 'Environment' }; $$k = $$r.OpenSubKey($$sk, $$true); if (-not $$k) { exit 0 }; try { $$raw = $$k.GetValue('Path', $$null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); if ($$null -eq $$raw) { exit 0 }; $$kind = try { $$k.GetValueKind('Path') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }; if ($$kind -ne [Microsoft.Win32.RegistryValueKind]::String -and $$kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) { $$kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }; $$tokens = @($$raw -split ';' | Where-Object { $$_ -ne '' }); $$kept = @($$tokens | Where-Object { -not $$_.Trim().TrimEnd([char]92).Equals($$d, [System.StringComparison]::OrdinalIgnoreCase) }); if ($$kept.Count -lt $$tokens.Count) { $$nv = $$kept -join ';'; if ($$nv -eq '') { $$k.DeleteValue('Path', $$false) } else { $$k.SetValue('Path', $$nv, $$kind) } } } finally { $$k.Close() }"`
    Pop $0

    System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_TARGET", p 0)'
    System::Call 'kernel32::SetEnvironmentVariable(t "LOOKER_PATH_SCOPE", p 0)'

    ${If} $0 == 0
      SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
    ${EndIf}
  ${EndIf}
!macroend
