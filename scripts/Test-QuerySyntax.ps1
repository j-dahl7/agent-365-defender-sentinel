[CmdletBinding()]
param([Parameter(Mandatory)][string]$KustoAssembly)
$ErrorActionPreference = 'Stop'
Add-Type -Path $KustoAssembly
$schema = '(TimeGenerated:datetime,SystemAlertId:string,ProviderName:string,AlertName:string,AlertType:string,AlertSeverity:string,CompromisedEntity:string,Description:string)'
$table = [Kusto.Language.Symbols.TableSymbol]::new('SecurityAlert', $schema, 'Synthetic documented SecurityAlert schema')
$database = [Kusto.Language.Symbols.DatabaseSymbol]::new('OfflineValidation', [Kusto.Language.Symbols.Symbol[]]@($table))
$state = [Kusto.Language.GlobalState]::Default.WithDatabase($database)
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../infra/sentinel-rules.bicep') -Raw
$queries = [regex]::Matches($source, "(?s)query:\s*'''\r?\n(.*?)\r?\n'''")
if ($queries.Count -ne 5) { throw 'Expected all five deployed queries.' }
foreach ($query in $queries) {
    $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($query.Groups[1].Value, $state, [Kusto.Language.Utils.CancellationToken]::new())
    $diagnostics = @($code.GetDiagnostics())
    if ($diagnostics.Count) {
        $diagnostics | Select-Object Code, Severity, Message | Format-Table
        throw 'A deployed rule failed offline semantic analysis.'
    }
    if ('CompromisedEntity' -notin $code.ResultType.Columns.Name) { throw 'AzureResource mapping references a missing result column.' }
}
Write-Host 'PASS: five deployed rules parse and bind against synthetic columns; no tenant query was run.'
