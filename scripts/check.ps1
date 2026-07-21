[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$SkipWpf,

    [switch]$SkipSmoke,

    [switch]$VerifyFormat
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$coreProject = Join-Path $repoRoot "LocalNetworkScanner.Core\LocalNetworkScanner.Core.csproj"
$cliProject = Join-Path $repoRoot "LocalNetworkScanner.Cli\LocalNetworkScanner.Cli.csproj"
$wpfProject = Join-Path $repoRoot "LocalNetworkScanner.Wpf\LocalNetworkScanner.Wpf.csproj"
$testResults = Join-Path $repoRoot "artifacts\TestResults"

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host ("> dotnet " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet exited with code $LASTEXITCODE."
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET SDK is required and dotnet was not found on PATH."
}

$projects = @($coreProject, $cliProject)
if (-not $SkipWpf) {
    if (-not (Test-Path -LiteralPath $wpfProject)) {
        throw "The WPF project was not found. Use -SkipWpf only for an intentional partial check."
    }
    $projects += $wpfProject
}

foreach ($project in $projects) {
    if (-not (Test-Path -LiteralPath $project)) {
        throw "Required project not found: $project"
    }
}

Push-Location $repoRoot
try {
    $sdkVersion = & dotnet --version
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to determine the .NET SDK version."
    }
    Write-Host "Using .NET SDK $sdkVersion" -ForegroundColor Cyan

    foreach ($project in $projects) {
        Invoke-DotNet @("restore", $project)
    }

    foreach ($project in $projects) {
        Invoke-DotNet @(
            "build",
            $project,
            "--configuration", $Configuration,
            "--no-restore",
            "--nologo"
        )
    }

    $testProjects = @(
        Get-ChildItem -Path $repoRoot -Recurse -File -Filter "*.Tests.csproj" |
            Where-Object {
                $_.FullName -notmatch "[\\/](bin|obj|artifacts)[\\/]"
            }
    )

    if ($testProjects.Count -eq 0) {
        throw "No test projects were found. Validation requires at least one test project."
    }
    else {
        New-Item -ItemType Directory -Path $testResults -Force | Out-Null
        foreach ($testProject in $testProjects) {
            Invoke-DotNet @("restore", $testProject.FullName)
            Invoke-DotNet @(
                "build",
                $testProject.FullName,
                "--configuration", $Configuration,
                "--no-restore",
                "--nologo"
            )

            [xml]$testProjectXml = Get-Content -LiteralPath $testProject.FullName -Raw
            $isTestProjectNodes = @(Select-Xml -Xml $testProjectXml -XPath "/Project/PropertyGroup/IsTestProject")
            $isTestProject = @($isTestProjectNodes | ForEach-Object { $_.Node.InnerText }) -contains "true"
            $hasTestSdk = @(Select-Xml -Xml $testProjectXml -XPath "/Project/ItemGroup/PackageReference[@Include='Microsoft.NET.Test.Sdk']").Count -gt 0
            $outputTypes = @(
                Select-Xml -Xml $testProjectXml -XPath "/Project/PropertyGroup/OutputType" |
                    ForEach-Object { $_.Node.InnerText }
            )
            $isExecutableHarness = $outputTypes -contains "Exe"

            if ($isTestProject -or $hasTestSdk) {
                $trxName = $testProject.BaseName + ".trx"
                $trxPath = Join-Path $testResults $trxName
                if (Test-Path -LiteralPath $trxPath) {
                    Remove-Item -LiteralPath $trxPath -Force
                }

                Invoke-DotNet @(
                    "test",
                    $testProject.FullName,
                    "--configuration", $Configuration,
                    "--no-build",
                    "--results-directory", $testResults,
                    "--logger", ("trx;LogFileName=" + $trxName),
                    "--nologo"
                )

                if (-not (Test-Path -LiteralPath $trxPath)) {
                    throw "The test runner did not create the expected TRX file: $trxPath"
                }
                [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
                $counters = $trx.TestRun.ResultSummary.Counters
                if ($null -eq $counters -or [int]$counters.total -lt 1) {
                    throw "The test project completed without executing any tests: $($testProject.FullName)"
                }
            }
            elseif ($isExecutableHarness) {
                Write-Host ("> executable test harness " + $testProject.BaseName) -ForegroundColor DarkGray
                $harnessOutput = @(
                    & dotnet run --project $testProject.FullName --configuration $Configuration --no-build 2>&1
                )
                $harnessExitCode = $LASTEXITCODE
                $harnessOutput | Out-Host
                if ($harnessExitCode -ne 0) {
                    throw "Executable test harness failed with code $harnessExitCode."
                }

                $summary = ($harnessOutput -join [Environment]::NewLine)
                if ($summary -match "(?im)(\d+)\s*/\s*(\d+)\s+test") {
                    if ([int]$Matches[2] -lt 1) {
                        throw "The executable test harness reported zero tests."
                    }
                }
                else {
                    Write-Warning "The executable test harness passed, but its test count could not be verified."
                }
            }
            else {
                throw "A *.Tests.csproj project was found but no supported test runner could be identified: $($testProject.FullName)"
            }
        }
    }

    if ($VerifyFormat) {
        $formatProjects = @($projects) + @($testProjects | ForEach-Object { $_.FullName })
        foreach ($project in @($formatProjects | Select-Object -Unique)) {
            Invoke-DotNet @(
                "format",
                $project,
                "--verify-no-changes",
                "--no-restore",
                "--verbosity", "minimal"
            )
        }
    }

    if (-not $SkipSmoke) {
        Write-Host "> CLI smoke test (--help)" -ForegroundColor DarkGray
        & dotnet run --project $cliProject --configuration $Configuration --no-build -- --help | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "CLI smoke test failed with code $LASTEXITCODE."
        }
    }

    Write-Host "Checks completed successfully." -ForegroundColor Green
}
finally {
    Pop-Location
}
