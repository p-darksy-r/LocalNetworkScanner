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
DefaultDirName={localappdata}\Programs\LocalNetworkScanner
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

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceRoot}\LocalNetworkScanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\LocalNetworkScanner.Cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Documentação"; Filename: "{app}\README.md"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

; Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
