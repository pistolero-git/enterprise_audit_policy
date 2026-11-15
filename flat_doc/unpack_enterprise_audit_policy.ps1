#requires -Version 5.1
<#
.SYNOPSIS
  Verify or restore the Enterprise Linux Audit Policy readable flat bundle.
.DESCRIPTION
  Extracts to a NEW isolated test directory, preserving the project root inside it.
  Validates the full bundle and all SHA-256 hashes BEFORE writing, then writes to a
  temporary sibling directory and moves it into place after successful extraction.
  Existing destinations are never overwritten. No audit rules are installed.
.EXAMPLE
  .\unpack_enterprise_audit_policy.ps1 -Bundle .\flat_doc\enterprise-audit-policy-v0.19-github-reviewed.flat.txt -VerifyOnly
.EXAMPLE
  .\unpack_enterprise_audit_policy.ps1 -Bundle .\flat_doc\enterprise-audit-policy-v0.19-github-reviewed.flat.txt -TestDir .\policy-test-01
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Bundle,

    [Alias('TestDir')]
    [string]$Output = './audit-policy-test-output',

    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)

function Read-BundleLine {
    param([System.IO.FileStream]$Stream)
    $bytes = [System.Collections.Generic.List[byte]]::new()
    while ($true) {
        $n = $Stream.ReadByte()
        if ($n -eq -1) {
            if ($bytes.Count -eq 0) { return $null }
            throw 'Unterminated flat-bundle metadata line'
        }
        if ($n -eq 10) {
            return $script:utf8.GetString($bytes.ToArray())
        }
        if ($bytes.Count -ge 16384) { throw 'Flat-bundle metadata line is too long' }
        $bytes.Add([byte]$n)
    }
}

function Test-BundlePath {
    param([string]$PathText)
    if ([string]::IsNullOrEmpty($PathText) -or $PathText.StartsWith('/') -or
        $PathText.Contains('\') -or $PathText.Contains(':')) {
        throw "Unsafe or empty bundle path: $PathText"
    }
    $parts = $PathText.Split('/')
    if ($parts.Count -lt 2) { throw "Bundle path lacks project folder: $PathText" }
    foreach ($part in $parts) {
        if ($part -eq '' -or $part -eq '.' -or $part -eq '..') {
            throw "Unsafe or noncanonical bundle path: $PathText"
        }
        foreach ($ch in $part.ToCharArray()) {
            if ([int]$ch -lt 32) { throw "Control character in bundle path: $PathText" }
        }
    }
}

function Read-FlatBundle {
    param([string]$BundlePath, [switch]$IncludeBytes)
    $stream = [System.IO.File]::Open(
        $BundlePath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $count = 0
    [long]$total = 0
    $rootName = $null
    try {
        $header = Read-BundleLine -Stream $stream
        if ($header -cne '@@AUDIT-POLICY-FLAT/1') { throw 'Unrecognized flat bundle header' }
        while ($true) {
            $line = Read-BundleLine -Stream $stream
            if ($null -eq $line) { throw 'Missing end-of-bundle record' }
            if ($line.StartsWith('@@END ', [System.StringComparison]::Ordinal)) {
                $footer = ConvertFrom-Json -InputObject $line.Substring(6)
                $footerFields = @($footer.PSObject.Properties.Name | Sort-Object)
                if (($footerFields -join ',') -cne 'file_count,total_bytes') { throw 'Unexpected footer fields' }
                if ([long]$footer.file_count -ne $count -or [long]$footer.total_bytes -ne $total) {
                    throw 'End record does not match file count and byte total'
                }
                if ($stream.ReadByte() -ne -1) { throw 'Extra data after end record' }
                return
            }
            if (-not $line.StartsWith('@@FILE ', [System.StringComparison]::Ordinal)) {
                throw "Invalid file record near entry $($count + 1)"
            }
            $meta = ConvertFrom-Json -InputObject $line.Substring(7)
            $fields = @($meta.PSObject.Properties.Name | Sort-Object)
            if (($fields -join ',') -cne 'path,sha256,size') { throw 'Unexpected file metadata fields' }
            $relativePath = [string]$meta.path
            Test-BundlePath -PathText $relativePath
            $thisRoot = $relativePath.Split('/')[0]
            if ($null -eq $rootName) { $rootName = $thisRoot }
            elseif ($rootName -cne $thisRoot) { throw 'More than one project root in bundle' }
            if (-not $seen.Add($relativePath)) { throw "Duplicate file path: $relativePath" }

            if ($meta.size -isnot [int] -and $meta.size -isnot [long]) {
                throw "Non-integer file size: $relativePath"
            }
            [long]$size = $meta.size
            if ($size -lt 0 -or $size -gt 100000000) { throw "Unsupported file size: $relativePath" }
            $expected = [string]$meta.sha256
            if (-not [System.Text.RegularExpressions.Regex]::IsMatch($expected, '^[0-9a-f]{64}$')) {
                throw "Invalid SHA-256: $relativePath"
            }
            $bytes = [byte[]]::new([int]$size)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $got = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($got -le 0) { throw "Truncated file: $relativePath" }
                $offset += $got
            }
            if ($stream.ReadByte() -ne 10) { throw "Missing record separator: $relativePath" }
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            try {
                $actual = [System.BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
            }
            finally { $hasher.Dispose() }
            if ($actual -cne $expected) { throw "SHA-256 mismatch: $relativePath" }

            $count++
            $total += $size
            if ($IncludeBytes) {
                Write-Output ([pscustomobject]@{ RelativePath = $relativePath; Bytes = $bytes })
            }
            else {
                Write-Output ([pscustomobject]@{ RelativePath = $relativePath; Bytes = $null })
            }
        }
    }
    finally { $stream.Dispose() }
}

$staging = $null
try {
    $bundleFull = [System.IO.Path]::GetFullPath($Bundle)
    if (-not [System.IO.File]::Exists($bundleFull)) { throw "Flat file not found: $bundleFull" }
    $verified = 0
    Read-FlatBundle -BundlePath $bundleFull | ForEach-Object { $verified++ }
    if ($VerifyOnly) {
        Write-Host "VALID: $verified files; no files written"
        exit 0
    }

    $outputFull = [System.IO.Path]::GetFullPath($Output)
    if ([System.IO.Directory]::Exists($outputFull) -or [System.IO.File]::Exists($outputFull)) {
        throw "Destination already exists: $outputFull. Choose a new -TestDir."
    }
    $parent = [System.IO.Path]::GetDirectoryName($outputFull)
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    $leaf = [System.IO.Path]::GetFileName($outputFull)
    $staging = [System.IO.Path]::Combine($parent, ".$leaf.staging-$([guid]::NewGuid().ToString('N'))")
    [System.IO.Directory]::CreateDirectory($staging) | Out-Null

    $separator = [System.IO.Path]::DirectorySeparatorChar
    $prefix = $staging.TrimEnd([char[]]@([char]'/', [char]'\')) + $separator
    $comparison = if ($separator -eq '\') { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $written = 0
    Read-FlatBundle -BundlePath $bundleFull -IncludeBytes | ForEach-Object {
        $native = $_.RelativePath.Replace('/', [string]$separator)
        $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($staging, $native))
        if (-not $target.StartsWith($prefix, $comparison)) { throw "Destination path escape: $($_.RelativePath)" }
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target)) | Out-Null
        [System.IO.File]::WriteAllBytes($target, [byte[]]$_.Bytes)
        $written++
    }
    if ([System.IO.Directory]::Exists($outputFull) -or [System.IO.File]::Exists($outputFull)) {
        throw "Destination created by another process: $outputFull"
    }
    [System.IO.Directory]::Move($staging, $outputFull)
    $staging = $null
    Write-Host "EXTRACTED: $written files to $outputFull"
    Write-Host 'No audit rules were installed or activated.'
    exit 0
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
finally {
    if ($null -ne $staging -and [System.IO.Directory]::Exists($staging)) {
        [System.IO.Directory]::Delete($staging, $true)
    }
}
