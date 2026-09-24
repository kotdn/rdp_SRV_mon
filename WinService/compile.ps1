# PowerShell компилятор для C# кода
Add-Type -AssemblyName System.ServiceProcess

# Для компиляции используем встроенный механизм
$sourceFile = "Program.cs"
$outputFile = "bin\Release\net8.0\WinService_new.exe"

Write-Host "Компилируем $sourceFile..."

# Используем встроенный CodeDomProvider для компиляции
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$compParams = New-Object System.CodeDom.Compiler.CompilerParameters
$compParams.OutputAssembly = $outputFile
$compParams.GenerateExecutable = $true
$compParams.IncludeDebugInformation = $false

# Добавляем необходимые assembly
$compParams.ReferencedAssemblies.Add("System.dll")
$compParams.ReferencedAssemblies.Add("System.ServiceProcess.dll")
$compParams.ReferencedAssemblies.Add("System.IO.dll")
$compParams.ReferencedAssemblies.Add("System.Diagnostics.EventLog.dll")

$sourceCode = Get-Content -Raw $sourceFile

$results = $provider.CompileAssemblyFromSource($compParams, $sourceCode)

if ($results.Errors.Count -eq 0) {
    Write-Host "Компиляция успешна!" -ForegroundColor Green
} else {
    Write-Host "Ошибки компиляции:" -ForegroundColor Red
    foreach ($error in $results.Errors) {
        Write-Host $error
    }
}
