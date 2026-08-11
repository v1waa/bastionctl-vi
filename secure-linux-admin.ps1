# Secure Linux Wizard — Windows administrator helper
# Мастер защиты Linux — помощник для Windows
#
# Creates an Ed25519 key, configures Windows OpenSSH/ssh-agent, writes a
# reversible SSH profile, copies the public key, tests login, and can upload
# and launch secure-linux-wizard.sh on the server.

[CmdletBinding()]
param(
    [string]$Language = "",
    [string]$Action = "menu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptVersion = "2026.08.10-2"
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$StateRoot = Join-Path $env:LOCALAPPDATA "SecureLinuxWizard"
$LogRoot = Join-Path $StateRoot "Logs"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$LogFile = Join-Path $LogRoot "admin-$Stamp.log"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($LogFile, "", $Utf8NoBom)

function Get-Message {
    param([Parameter(Mandatory)][string]$Key, [string]$Value = "")
    $Ru = @{
        ChooseLanguage = "Выберите язык / Choose language"
        ChooseAction = "Что настроить?"
        Admin = "Admin's PC — SSH-ключ, ssh-agent и профиль"
        Server = "Server — загрузить и запустить Bash-мастер на сервере"
        Test = "Проверить существующее SSH-подключение"
        Invalid = "Введите один из предложенных номеров."
        Alias = "Короткое имя подключения (например, myvps)"
        Host = "IP-адрес или домен сервера"
        User = "SSH-пользователь сервера"
        Port = "Порт SSH"
        KeyPath = "Путь нового/существующего приватного ключа"
        Generate = "Создать новый Ed25519-ключ?"
        Copy = "Скопировать открытый ключ на сервер сейчас? Потребуется текущий пароль сервера"
        Agent = "Кодовая фраза не сохраняется скриптом. Windows ssh-agent управляет ключом; ssh-add попросит фразу безопасно."
        AgentAdmin = "Не удалось включить ssh-agent. Откройте PowerShell от администратора и выполните: Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent"
        Target = "SSH-цель: имя профиля либо user@host"
        Upload = "Загрузить secure-linux-wizard.sh в /tmp и запустить через sudo?"
        NoBash = "Рядом с PowerShell-файлом не найден secure-linux-wizard.sh. Распакуйте весь комплект в одну папку."
        KeepSession = "Не закрывайте текущий SSH-сеанс, пока не проверите новый вход в отдельном окне."
        Done = "Готово. Подключение: ssh"
        Log = "Подробный журнал"
        YesNo = "Д/н"
        NoYes = "д/Н"
        TestOk = "Подключение по ключу работает."
        TestFail = "Автотест не прошёл. Проверьте профиль и повторите вручную."
    }
    $En = @{
        ChooseLanguage = "Choose language / Выберите язык"
        ChooseAction = "What do you want to configure?"
        Admin = "Admin's PC — SSH key, ssh-agent, and profile"
        Server = "Server — upload and start the Bash wizard on the server"
        Test = "Test an existing SSH connection"
        Invalid = "Enter one of the listed numbers."
        Alias = "Connection alias (for example, myvps)"
        Host = "Server IP address or hostname"
        User = "Server SSH username"
        Port = "SSH port"
        KeyPath = "Path to the new/existing private key"
        Generate = "Generate a new Ed25519 key?"
        Copy = "Copy the public key to the server now? The current server password may be required"
        Agent = "The script never stores your passphrase. Windows ssh-agent manages the key; ssh-add requests the passphrase securely."
        AgentAdmin = "Could not enable ssh-agent. Open PowerShell as Administrator and run: Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent"
        Target = "SSH target: profile alias or user@host"
        Upload = "Upload secure-linux-wizard.sh to /tmp and launch it through sudo?"
        NoBash = "secure-linux-wizard.sh was not found beside this PowerShell file. Extract the whole package into one folder."
        KeepSession = "Do not close the current SSH session until a new login succeeds in a separate window."
        Done = "Complete. Connect with: ssh"
        Log = "Detailed log"
        YesNo = "Y/n"
        NoYes = "y/N"
        TestOk = "Key-based connection works."
        TestFail = "The automatic test failed. Review the profile and retry manually."
    }
    $Table = if ($script:Language -eq "ru") { $Ru } else { $En }
    if (-not $Table.ContainsKey($Key)) { return $Key }
    if ($Value) { return "$($Table[$Key]) $Value" }
    return $Table[$Key]
}

function Write-LogLine {
    param([Parameter(Mandatory)][string]$Level, [Parameter(Mandatory)][string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    $Line = "{0} [{1}] {2}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $Level, $Text
    Write-Host $Line -ForegroundColor $Color
    [System.IO.File]::AppendAllText($LogFile, $Line + [Environment]::NewLine, $Utf8NoBom)
}
function Write-Info([string]$Text) { Write-LogLine "INFO" $Text Cyan }
function Write-Ok([string]$Text) { Write-LogLine " OK " $Text Green }
function Write-Warn([string]$Text) { Write-LogLine "WARN" $Text Yellow }

function Read-Value {
    param([Parameter(Mandatory)][string]$Prompt, [string]$Default = "")
    $Label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    $Answer = Read-Host $Label
    if ([string]::IsNullOrWhiteSpace($Answer)) { return $Default }
    return $Answer.Trim()
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$DefaultYes = $false)
    $Hint = if ($DefaultYes) { Get-Message "YesNo" } else { Get-Message "NoYes" }
    while ($true) {
        $Answer = (Read-Host "$Prompt [$Hint]").Trim().ToLowerInvariant()
        if (-not $Answer) { return $DefaultYes }
        if ($Answer -in @("y", "yes", "д", "да")) { return $true }
        if ($Answer -in @("n", "no", "н", "нет")) { return $false }
        Write-Warn (Get-Message "Invalid")
    }
}

function Write-Utf8File {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Assert-OpenSsh {
    foreach ($Command in @("ssh.exe", "ssh-keygen.exe", "scp.exe")) {
        if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
            throw "OpenSSH command is missing / Команда OpenSSH отсутствует: $Command. Install Windows Optional Feature 'OpenSSH Client'."
        }
    }
}

function Assert-Port([string]$Port) {
    $Number = 0
    if (-not [int]::TryParse($Port, [ref]$Number) -or $Number -lt 1 -or $Number -gt 65535) {
        throw "Invalid port / Недопустимый порт: $Port"
    }
}

function Enable-SshAgent {
    param([Parameter(Mandatory)][string]$KeyPath)
    Write-Info (Get-Message "Agent")
    try {
        $Service = Get-Service ssh-agent -ErrorAction Stop
        if ($Service.StartType -ne "Automatic") { Set-Service ssh-agent -StartupType Automatic }
        if ($Service.Status -ne "Running") { Start-Service ssh-agent }
        & ssh-add.exe $KeyPath
        if ($LASTEXITCODE -ne 0) { throw "ssh-add exit code $LASTEXITCODE" }
        Write-Ok "ssh-agent: $KeyPath"
    }
    catch {
        Write-Warn (Get-Message "AgentAdmin")
        Write-Warn $_.Exception.Message
    }
}

function Write-SshProfile {
    param(
        [Parameter(Mandatory)][string]$Alias,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Port,
        [Parameter(Mandatory)][string]$KeyPath
    )
    $SshDir = Join-Path $env:USERPROFILE ".ssh"
    $DropDir = Join-Path $SshDir "config.d"
    $Config = Join-Path $SshDir "config"
    $Profile = Join-Path $DropDir "$Alias.conf"
    New-Item -ItemType Directory -Force -Path $DropDir | Out-Null
    if (Test-Path $Config) {
        Copy-Item $Config "$Config.backup-$Stamp" -Force
        $Current = [System.IO.File]::ReadAllText($Config)
    }
    else { $Current = "" }
    if ($Current -notmatch '(?m)^\s*Include\s+~/.ssh/config\.d/\*\s*$') {
        $Current = "Include ~/.ssh/config.d/*`r`n" + $Current
        Write-Utf8File $Config $Current
    }
    $Identity = $KeyPath.Replace('\', '/')
    $Body = @"
Host $Alias
    HostName $HostName
    User $UserName
    Port $Port
    IdentityFile $Identity
    IdentitiesOnly yes
    AddKeysToAgent yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
"@
    Write-Utf8File $Profile ($Body.Trim() + "`r`n")
    Write-Ok "SSH profile: $Profile"
}

function New-OrReuseKey {
    param([Parameter(Mandatory)][string]$KeyPath, [Parameter(Mandatory)][string]$Alias)
    $Parent = Split-Path -Parent $KeyPath
    if ([string]::IsNullOrWhiteSpace($Parent)) { $Parent = (Get-Location).Path }
    New-Item -ItemType Directory -Force -Path $Parent | Out-Null
    if (-not (Test-Path $KeyPath)) {
        if (-not (Read-YesNo (Get-Message "Generate") $true)) { throw "Private key is required / Требуется приватный ключ" }
        Write-Info (Get-Message "Agent")
        $Comment = "$env:USERNAME@$env:COMPUTERNAME-$Alias"
        & ssh-keygen.exe -t ed25519 -a 100 -f $KeyPath -C $Comment
        if ($LASTEXITCODE -ne 0) { throw "ssh-keygen exit code $LASTEXITCODE" }
    }
    $PublicPath = "$KeyPath.pub"
    if (-not (Test-Path $PublicPath)) {
        $Public = & ssh-keygen.exe -y -f $KeyPath
        if ($LASTEXITCODE -ne 0) { throw "Could not derive public key / Не удалось получить открытый ключ" }
        Write-Utf8File $PublicPath (($Public -join "`n") + "`n")
    }
    try {
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $KeyPath /inheritance:r /grant:r "${Identity}:(F)" | Out-Null
    }
    catch { Write-Warn "Could not tighten the private-key ACL automatically / Не удалось автоматически изменить ACL ключа" }
    & ssh-keygen.exe -lf $PublicPath
    return $PublicPath
}

function Configure-AdminPc {
    Assert-OpenSsh
    $Alias = Read-Value (Get-Message "Alias") "myvps"
    if ($Alias -notmatch '^[A-Za-z0-9._-]+$') { throw "Invalid alias / Недопустимое имя подключения" }
    $HostName = Read-Value (Get-Message "Host")
    if (-not $HostName -or $HostName -match '\s') { throw "Server host is required / Укажите адрес сервера" }
    $UserName = Read-Value (Get-Message "User") "admin"
    if ($UserName -notmatch '^[a-z_][a-z0-9_-]{0,31}$') { throw "Invalid user / Недопустимый пользователь" }
    $Port = Read-Value (Get-Message "Port") "22"
    Assert-Port $Port
    $DefaultKey = Join-Path $env:USERPROFILE ".ssh\${Alias}_ed25519"
    $KeyPath = Read-Value (Get-Message "KeyPath") $DefaultKey
    $PublicPath = New-OrReuseKey $KeyPath $Alias
    Write-SshProfile $Alias $HostName $UserName $Port $KeyPath
    Enable-SshAgent $KeyPath
    if (Read-YesNo (Get-Message "Copy") $true) {
        Write-Info "Copying public key; only the .pub file is sent / Копируется только открытый .pub-ключ"
        Get-Content -Raw $PublicPath | & ssh.exe -p $Port "$UserName@$HostName" 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; IFS= read -r key; grep -qxF -- "$key" ~/.ssh/authorized_keys || printf "%s\n" "$key" >> ~/.ssh/authorized_keys'
        if ($LASTEXITCODE -ne 0) { Write-Warn "Public-key copy failed / Копирование ключа не удалось" }
    }
    & ssh.exe -o BatchMode=yes -o IdentitiesOnly=yes -i $KeyPath -p $Port "$UserName@$HostName" true
    if ($LASTEXITCODE -eq 0) { Write-Ok (Get-Message "TestOk") } else { Write-Warn (Get-Message "TestFail") }
    Write-Ok "$(Get-Message 'Done') $Alias"
    Write-Warn (Get-Message "KeepSession")
}

function Start-ServerWizard {
    Assert-OpenSsh
    $BashScript = Join-Path $PSScriptRoot "secure-linux-wizard.sh"
    if (-not (Test-Path $BashScript)) { throw (Get-Message "NoBash") }
    $Target = Read-Value (Get-Message "Target") "myvps"
    if ($Target -notmatch '^(?!-)[A-Za-z0-9_.:@\[\]-]+$') { throw "Invalid SSH target / Недопустимая SSH-цель: $Target" }
    if (-not (Read-YesNo (Get-Message "Upload") $true)) { return }
    Write-Warn (Get-Message "KeepSession")
    & scp.exe $BashScript "${Target}:/tmp/secure-linux-wizard.sh"
    if ($LASTEXITCODE -ne 0) { throw "scp failed / scp завершился ошибкой" }
    & ssh.exe -t $Target "sudo bash /tmp/secure-linux-wizard.sh"
    if ($LASTEXITCODE -ne 0) { Write-Warn "Remote wizard returned exit code $LASTEXITCODE / Удалённый мастер вернул код $LASTEXITCODE" }
}

function Test-SshConnection {
    Assert-OpenSsh
    $Target = Read-Value (Get-Message "Target") "myvps"
    if ($Target -notmatch '^(?!-)[A-Za-z0-9_.:@\[\]-]+$') { throw "Invalid SSH target / Недопустимая SSH-цель: $Target" }
    & ssh.exe -o BatchMode=yes $Target "whoami"
    if ($LASTEXITCODE -eq 0) { Write-Ok (Get-Message "TestOk") } else { Write-Warn (Get-Message "TestFail") }
}

if ($Language -notin @("ru", "en")) {
    Write-Host "`n$(Get-Message 'ChooseLanguage')`n  1) Русский`n  2) English"
    $Choice = Read-Host ">"
    $Language = if ($Choice -eq "1" -or $Choice.ToLowerInvariant() -eq "ru") { "ru" } else { "en" }
}
$script:Language = $Language
Write-Info "Secure Linux Wizard Windows helper $ScriptVersion"
Write-Info "$(Get-Message 'Log'): $LogFile"

if ($Action -eq "menu") {
    Write-Host "`n$(Get-Message 'ChooseAction')`n  1) $(Get-Message 'Admin')`n  2) $(Get-Message 'Server')`n  3) $(Get-Message 'Test')"
    $Choice = Read-Host ">"
    $Action = switch ($Choice) {
        "1" { "admin" }
        "2" { "server" }
        "3" { "test" }
        default { throw (Get-Message "Invalid") }
    }
}

try {
    switch ($Action.ToLowerInvariant()) {
        "admin" { Configure-AdminPc }
        "server" { Start-ServerWizard }
        "test" { Test-SshConnection }
        default { throw "Unknown action / Неизвестное действие: $Action" }
    }
}
catch {
    Write-LogLine "ERR " $_.Exception.Message Red
    exit 1
}
