; Inno Setup recipe for the Windows installer. Run it through packaging/build_windows.py,
; which supplies the values written here as {#...}.

[Setup]
AppId={{7F3B9C52-6E1D-4A8F-B0C4-2D95E1A7C364}
AppName=mindyourownbytes
AppVersion={#AppVersion}
AppVerName=mindyourownbytes {#AppVersion}
AppPublisher=mindyourownbytes contributors
AppPublisherURL=https://github.com/N-Bermparis/mindyourownbytes
AppSupportURL=https://github.com/N-Bermparis/mindyourownbytes/issues
AppUpdatesURL=https://github.com/N-Bermparis/mindyourownbytes/releases
; The app holds this while it's open, so Setup and Uninstall both ask to close it first.
AppMutex=mindyourownbytes-running

; Installs for the current user only, so it never asks for administrator approval.
PrivilegesRequired=lowest
DefaultDirName={autopf}\mindyourownbytes
DisableDirPage=yes
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809, the oldest version Qt supports.
MinVersion=10.0.17763

OutputBaseFilename={#BaseName}-setup
SetupIconFile=app.ico
UninstallDisplayIcon={app}\mindyourownbytes.exe
UninstallDisplayName=mindyourownbytes
; Follows the system's light or dark mode, like the app.
WizardStyle=modern dynamic
WizardSmallImageFile=wizard-small-58.png,wizard-small-116.png
WizardImageFile=wizard-large-164.png,wizard-large-328.png
Compression=lzma2/max
SolidCompression=yes
VersionInfoVersion={#NumericVersion}
VersionInfoDescription=mindyourownbytes installer
VersionInfoCopyright=GPL-3.0-or-later

[Files]
Source: "{#AppFolder}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Libraries from an older version must not sit beside the new ones, where one could get
; loaded by accident. People's own files and vault are never in this folder.
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\gnupg"

[Icons]
; The ID matches the one the app sets, so a pinned icon and the running window are one taskbar button.
Name: "{autoprograms}\mindyourownbytes"; Filename: "{app}\mindyourownbytes.exe"; AppUserModelID: "mindyourownbytes.app"

[Run]
Filename: "{app}\mindyourownbytes.exe"; Description: "Open mindyourownbytes"; Flags: nowait postinstall skipifsilent

[Code]
function IsFileInUse(const FileName: String): Boolean;
var
  Stream: TFileStream;
begin
  Result := False;
  if FileExists(FileName) then
    try
      Stream := TFileStream.Create(FileName, fmOpenReadWrite or fmShareExclusive);
      Stream.Free;
    except
      Result := True;
    end;
end;

function IsIncludedGnuPGRunning(const Bin: String): Boolean;
begin
  Result := IsFileInUse(Bin + 'gpg-agent.exe') or IsFileInUse(Bin + 'keyboxd.exe') or IsFileInUse(Bin + 'scdaemon.exe');
end;

{ GnuPG keeps helpers running in the background, which would lock the files being replaced.
  A GnuPG from elsewhere, such as Gpg4win, is left alone: only this folder's copy is checked. }
procedure StopIncludedGnuPG;
var
  Bin: String;
  ResultCode, Attempts: Integer;
begin
  Bin := ExpandConstant('{app}\gnupg\bin\');
  if IsIncludedGnuPGRunning(Bin) then
  begin
    Exec(Bin + 'gpgconf.exe', '--kill all', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Attempts := 0;
    while IsIncludedGnuPGRunning(Bin) and (Attempts < 50) do
    begin
      Sleep(100);
      Attempts := Attempts + 1;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopIncludedGnuPG;
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopIncludedGnuPG;
end;
