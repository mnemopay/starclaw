; StarClaw for Windows: per-user installer (no admin prompt).
;   iscc /DAppVersion=2.0.0-alpha.8 /DStaging=<staging dir> installer\windows\starclaw.iss
; Program files go to %LOCALAPPDATA%\Programs\StarClaw. The user's data (console key, model key, audit
; log, workspace) lives in %LOCALAPPDATA%\StarClaw, which `starclaw app` uses; uninstalling never deletes it.
; Silent install can pass the model key: /VERYSILENT /GROQKEY=gsk_...

#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef Staging
  #error Pass /DStaging=<staging dir from build.ps1>
#endif

[Setup]
AppId={{6E4A1F7C-3B2D-4C8E-9A51-5D7F0C2B8E14}
AppName=StarClaw
AppVersion={#AppVersion}
AppPublisher=J&B Enterprise LLC
AppPublisherURL=https://starclaw.dev
DefaultDirName={localappdata}\Programs\StarClaw
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=StarClaw-Setup-{#AppVersion}
OutputDir=output
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=StarClaw {#AppVersion}
UninstallDisplayIcon={app}\node\node.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"

[Files]
Source: "{#Staging}\node\*"; DestDir: "{app}\node"; Flags: recursesubdirs ignoreversion
Source: "{#Staging}\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs ignoreversion
Source: "{#Staging}\StarClaw.cmd"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; An upgrade replaces the bundled app completely (no stale files from the previous version).
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\node"

[Icons]
Name: "{autoprograms}\StarClaw"; Filename: "{app}\StarClaw.cmd"; WorkingDir: "{app}"; IconFilename: "{app}\node\node.exe"
Name: "{autodesktop}\StarClaw"; Filename: "{app}\StarClaw.cmd"; WorkingDir: "{app}"; IconFilename: "{app}\node\node.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\StarClaw.cmd"; WorkingDir: "{app}"; Description: "Start StarClaw now"; Flags: postinstall nowait skipifsilent shellexec

[Code]
var
  KeyPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  KeyPage := CreateInputQueryPage(wpSelectTasks, 'AI model key', 'StarClaw needs a key for its AI model.',
    'StarClaw uses Groq by default. Paste your Groq API key (create one at console.groq.com/keys), or leave it empty ' +
    'and add a line GROQ_API_KEY=... to %LOCALAPPDATA%\StarClaw\.env later. The key is stored only on this PC.');
  KeyPage.Add('Groq API key (optional):', True);
end;

function KeyIsValid(Key: String): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := Length(Key) <= 256;
  for I := 1 to Length(Key) do
  begin
    C := Key[I];
    if not (((C >= 'a') and (C <= 'z')) or ((C >= 'A') and (C <= 'Z')) or ((C >= '0') and (C <= '9')) or (C = '_') or (C = '-')) then
      Result := False;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = KeyPage.ID) and not KeyIsValid(Trim(KeyPage.Values[0])) then
  begin
    MsgBox('That does not look like an API key (letters, digits, _ and - only). Paste it again or leave the field empty.', mbError, MB_OK);
    Result := False;
  end;
end;

{ Adds GROQ_API_KEY to %LOCALAPPDATA%\StarClaw\.env unless that file already sets one. Never rewrites the file. }
procedure WriteModelKey(Key: String);
var
  Dir, EnvFile: String;
  Existing, Prefix: AnsiString;
begin
  Key := Trim(Key);
  if (Key = '') or not KeyIsValid(Key) then
    Exit;
  Dir := ExpandConstant('{localappdata}\StarClaw');
  ForceDirectories(Dir);
  EnvFile := Dir + '\.env';
  Existing := '';
  if FileExists(EnvFile) then
    LoadStringFromFile(EnvFile, Existing);
  if Pos('GROQ_API_KEY=', Existing) > 0 then
  begin
    Log('GROQ_API_KEY is already set in ' + EnvFile + '; left unchanged');
    Exit;
  end;
  Prefix := '';
  if (Length(Existing) > 0) and (Existing[Length(Existing)] <> #10) then
    Prefix := #13#10;
  if SaveStringToFile(EnvFile, Prefix + 'GROQ_API_KEY=' + Key + #13#10, True) then
    Log('model key written to ' + EnvFile)
  else
    Log('could not write ' + EnvFile);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Key: String;
begin
  if CurStep = ssPostInstall then
  begin
    Key := KeyPage.Values[0];
    if Trim(Key) = '' then
      Key := ExpandConstant('{param:GROQKEY|}');
    WriteModelKey(Key);
  end;
end;
