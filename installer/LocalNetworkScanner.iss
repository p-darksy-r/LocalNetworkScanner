; Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

#ifndef SourceRoot
  #error SourceRoot must point to the staged release directory.
#endif
#ifndef OutputDirectory
  #error OutputDirectory must be provided.
#endif
#ifndef AppVersion
  #error AppVersion must be provided.
#endif
#ifndef RuntimeIdentifier
  #error RuntimeIdentifier must be provided.
#endif
#ifndef OutputBaseFilename
  #error OutputBaseFilename must be provided.
#endif
#ifndef SetupIconFile
  #error SetupIconFile must be provided.
#endif

#define AppName "Local Network Scanner"
#define AppPublisher "p-darksy-r"
#define AppUrl "https://github.com/p-darksy-r/LocalNetworkScanner"
#define AppExeName "LocalNetworkScanner.exe"
#define AppInstallDirectory "{localappdata}\Programs\LocalNetworkScanner"
#define AppUninstallRegistryKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\{4CA46B3E-3522-4E1B-99B7-CBE0A34B5981}_is1"
#define AppVersionPacked StrToVersion(AppVersion + ".0")

[Setup]
AppId={{4CA46B3E-3522-4E1B-99B7-CBE0A34B5981}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
LicenseFile={#SourceRoot}\LICENSE
DefaultDirName={#AppInstallDirectory}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDirectory}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#SetupIconFile}
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
ChangesEnvironment=no
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} installer ({#RuntimeIdentifier})
VersionInfoCopyright=Copyright (c) 2026 p-darksy-r and Local Network Scanner.
VersionInfoProductName={#AppName}
#ifdef SignToolName
SignTool={#SignToolName}
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif

#if RuntimeIdentifier == "win-x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#elif RuntimeIdentifier == "win-arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
  #error Unsupported RuntimeIdentifier.
#endif

[Languages]
Name: "portugues"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
portugues.DowngradeBlocked=Já está instalada a versão %1. Para proteger definições e dados locais, este instalador mais antigo (%2) não pode substituí-la.
english.DowngradeBlocked=Version %1 is already installed. To protect local settings and data, this older installer (%2) cannot replace it.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceRoot}\LocalNetworkScanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\LocalNetworkScanner.Cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\tools\*"; DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Documentação"; Filename: "{app}\README.md"
Name: "{group}\Ajuda - erro 4551 e App Control"; Filename: "{app}\docs\APP_CONTROL.md"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Code]
const
  DriveRemovable = 2;
  DriveFixed = 3;
  DriveCdRom = 5;
  DriveRamDisk = 6;

function GetDriveTypeW(RootPathName: String): Cardinal;
external 'GetDriveTypeW@kernel32.dll stdcall';

function IsAsciiLetter(Character: Char): Boolean;
begin
  Result := ((Character >= 'A') and (Character <= 'Z')) or
            ((Character >= 'a') and (Character <= 'z'));
end;

function TryNormalizeLocalInstallDirectory(
  const Candidate: String;
  var Normalized: String): Boolean;
var
  Trimmed: String;
  DriveType: Integer;
begin
  Result := False;
  Normalized := '';
  Trimmed := Trim(Candidate);

  { Only accept an absolute drive path. This rejects UNC/device paths and avoids
    contacting a remote share when the per-user uninstall key was tampered with. }
  if (Length(Trimmed) < 3) or
     (not IsAsciiLetter(Trimmed[1])) or
     (Trimmed[2] <> ':') or
     (Trimmed[3] <> '\') then
  begin
    Exit;
  end;

  DriveType := GetDriveTypeW(Copy(Trimmed, 1, 3));
  if (DriveType <> DriveRemovable) and
     (DriveType <> DriveFixed) and
     (DriveType <> DriveCdRom) and
     (DriveType <> DriveRamDisk) then
  begin
    Exit;
  end;

  Normalized := ExpandFileName(Trimmed);
  Result := True;
end;

procedure ConsiderInstalledExecutable(
  const ExecutablePath: String;
  var HasInstalledVersion: Boolean;
  var InstalledVersion: Int64);
var
  CandidateVersion: Int64;
begin
  if GetPackedVersion(ExecutablePath, CandidateVersion) and
     ((not HasInstalledVersion) or
      (ComparePackedVersion(CandidateVersion, InstalledVersion) > 0)) then
  begin
    HasInstalledVersion := True;
    InstalledVersion := CandidateVersion;
  end;
end;

procedure ConsiderRegisteredInstallLocation(
  RootKey: Integer;
  var HasInstalledVersion: Boolean;
  var InstalledVersion: Int64);
var
  RegisteredDirectory: String;
  LocalDirectory: String;
begin
  if not RegQueryStringValue(
       RootKey,
       '{#AppUninstallRegistryKey}',
       'InstallLocation',
       RegisteredDirectory) then
  begin
    Exit;
  end;

  if not TryNormalizeLocalInstallDirectory(RegisteredDirectory, LocalDirectory) then
  begin
    Log('Ignored an invalid or non-local registered install location.');
    Exit;
  end;

  ConsiderInstalledExecutable(
    AddBackslash(LocalDirectory) + '{#AppExeName}',
    HasInstalledVersion,
    InstalledVersion);
end;

function InitializeSetup(): Boolean;
var
  HasInstalledVersion: Boolean;
  InstalledVersion: Int64;
begin
  Result := True;
  HasInstalledVersion := False;
  InstalledVersion := 0;

  { Inno writes per-user uninstall data to the registry view matching the
    installer architecture. Query both views so upgrades remain protected when
    moving between historical x86/x64-compatible and ARM64 packages. }
  if IsWin64 then
  begin
    ConsiderRegisteredInstallLocation(
      HKCU64, HasInstalledVersion, InstalledVersion);
    ConsiderRegisteredInstallLocation(
      HKCU32, HasInstalledVersion, InstalledVersion);
  end
  else
  begin
    ConsiderRegisteredInstallLocation(
      HKCU, HasInstalledVersion, InstalledVersion);
  end;

  { Keep the deterministic default as a fallback for incomplete legacy
    uninstall records and first-party packages created before InstallLocation. }
  ConsiderInstalledExecutable(
    AddBackslash(ExpandConstant('{#AppInstallDirectory}')) + '{#AppExeName}',
    HasInstalledVersion,
    InstalledVersion);

  if HasInstalledVersion and
     (ComparePackedVersion(InstalledVersion, {#AppVersionPacked}) > 0) then
  begin
    Log(
      'Downgrade blocked: installed=' + VersionToStr(InstalledVersion) +
      ', setup={#AppVersion}.');
    if not WizardSilent then
      MsgBox(
        FmtMessage(
          CustomMessage('DowngradeBlocked'), [VersionToStr(InstalledVersion), '{#AppVersion}']),
        mbError,
        MB_OK);
    Result := False;
  end;
end;

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
