#define MyAppName "PhilSys PAMANA Utility"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "PhilSys"
#define MyAppExeName "nas_transfer_gui.exe"
#define MyAppIcon "assets\pamana_logo.ico"

[Setup]
AppId={{9F82B3E1-4D6F-4B52-9A8C-8F7E6D5C4B3A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.\Output
OutputBaseFilename=PhilSys_PAMANA_Utility_Setup
SetupIconFile={#MyAppIcon}
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "startmenuicon"; Description: "Create a Start Menu folder shortcut"; GroupDescription: "Additional shortcuts:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "dist\nas_transfer_gui\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\nas_transfer_gui\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
