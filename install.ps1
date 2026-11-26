$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2+ on Windows PowerShell 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$baseUrl = 'https://github.com/x7ssss/looker/releases/latest/download'
$binaryName = 'looker-windows-x64.exe'
$binaryUrl = "$baseUrl/$binaryName"
$checksumsUrl = "$baseUrl/checksums.sha256"

$installDir = Join-Path $env:LOCALAPPDATA 'looker\bin'
$destPath = Join-Path $installDir 'looker.exe'

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('looker-install-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    $tempExe = Join-Path $tempDir $binaryName
    $tempSums = Join-Path $tempDir 'checksums.sha256'

    Write-Host "Downloading $binaryName and checksums from latest GitHub release..."
    $iwrParams = @{ UseBasicParsing = $true }
    Invoke-WebRequest @iwrParams -Uri $checksumsUrl -OutFile $tempSums
    Invoke-WebRequest @iwrParams -Uri $binaryUrl -OutFile $tempExe

    $expectedHash = $null
    foreach ($line in Get-Content -Path $tempSums -Encoding UTF8) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?looker-windows-x64\.exe\s*$') {
            $expectedHash = $Matches[1].ToLowerInvariant()
            break
        }
    }
    if (-not $expectedHash) {
        throw "Could not find SHA-256 entry for $binaryName in checksums.sha256. Aborting installation."
    }

    $actualHash = (Get-FileHash -Path $tempExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed for $binaryName! Expected: $expectedHash, Actual: $actualHash. Aborting installation."
    }
    Write-Host "Verified SHA-256: $actualHash"

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item -Path $tempExe -Destination $destPath -Force

    # Add $installDir to HKCU\Environment\Path without expanding %VARS% or changing REG_EXPAND_SZ
    $normalizedTarget = $installDir.Trim().TrimEnd([char]92)
    $envKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if (-not $envKey) {
        $envKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
    }
    $pathUpdated = $false
    try {
        $rawPath = $envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $valueKind = try {
            $envKey.GetValueKind('Path')
        } catch {
            [Microsoft.Win32.RegistryValueKind]::ExpandString
        }
        if ($valueKind -ne [Microsoft.Win32.RegistryValueKind]::String -and $valueKind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) {
            $valueKind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        }

        $parts = @()
        if ($rawPath) {
            $parts = @($rawPath -split ';' | Where-Object { $_ -ne '' })
        }
        $alreadyOnPath = $parts | Where-Object { $_.Trim().TrimEnd([char]92).Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase) }
        if (-not $alreadyOnPath) {
            $newPath = (@($parts) + @($normalizedTarget)) -join ';'
            $envKey.SetValue('Path', $newPath, $valueKind)
            $pathUpdated = $true
        }
    } finally {
        $envKey.Close()
    }

    if ($pathUpdated) {
        try {
            $sig = '[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
            $native = Add-Type -MemberDefinition $sig -Name 'Win32Broadcast' -Namespace 'LookerInstaller' -PassThru
            $res = [UIntPtr]::Zero
            $null = $native::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 0x0002, 5000, [ref]$res)
        } catch {
            # Non-fatal if restricted by policy; new logins/terminals still read HKCU\Environment\Path
        }
    }

    Write-Host ""
    Write-Host "Looker CLI installed successfully to: $destPath" -ForegroundColor Green
    if ($pathUpdated) {
        Write-Host "Added '$installDir' to your user PATH."
    } else {
        Write-Host "'$installDir' is already on your user PATH."
    }
    Write-Host "Open a new terminal window and run: looker --help"
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
