param(
    [Parameter(Mandatory = $true)]
    [string]$AssemblyPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

if (-not (Test-Path -LiteralPath $AssemblyPath))
{
    throw "File not found: $AssemblyPath"
}
if (-not (Test-Path -LiteralPath $OutputDir))
{
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$OutputDir = (Resolve-Path $OutputDir).Path
$fullPath = (Resolve-Path $AssemblyPath).Path
$counter = 0

function Save-Resource
{
    param([string]$Name, [byte[]]$Buffer, [string]$OutputDir)

    $safeName = ($Name -replace '[\\/:*?"<>|]', '_')
    $outPath = Join-Path $OutputDir $safeName
    [System.IO.File]::WriteAllBytes($outPath, $Buffer)
    Write-Host "Extracted '$Name' ($($Buffer.Length) bytes) -> $outPath"
}

if ($PSVersionTable.PSEdition -eq 'Core')
{
    #PowerShell 7
    #Parses the PE/COFF file directly using System.Reflection.Metadata
    #No CLR loading occurs, making execution impossible
    Add-Type -AssemblyName System.Reflection.Metadata -ErrorAction SilentlyContinue

    $assemblyFileStream = [System.IO.File]::OpenRead($fullPath)
    try
    {
        $peReader = [System.Reflection.PortableExecutable.PEReader]::new($assemblyFileStream)
        try
        {
            if (-not $peReader.HasMetadata)
            {
                throw "'$AssemblyPath' has no CLR metadata. This is not a managed assembly."
            }

            $mdReader = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($peReader)
            $corHeader = $peReader.PEHeaders.CorHeader

            if ($null -eq $corHeader -or $corHeader.ResourcesDirectory.Size -le 0)
            {
                Write-Host "No embedded resource data section found in $AssemblyPath"
                return
            }

            $resourcesBlock = $peReader.GetSectionData($corHeader.ResourcesDirectory.RelativeVirtualAddress)
            $handles = $mdReader.ManifestResources

            foreach ($handle in $handles)
            {
                $resource = $mdReader.GetManifestResource($handle)
                $name = $mdReader.GetString($resource.Name)

                if (-not $resource.Implementation.IsNil)
                {
                    Write-Warning "Skipping '$name' because it is linked externally."
                    continue
                }

                $localReader = $resourcesBlock.GetReader([int]$resource.Offset, 4)
                $length = $localReader.ReadUInt32()

                $dataReader = $resourcesBlock.GetReader([int]$resource.Offset + 4, [int]$length)
                $buffer = [byte[]]::new($length)
                $dataReader.ReadBytes([int]$length, $buffer, 0)

                Save-Resource -Name $name -Buffer $buffer -OutputDir $OutputDir
                $counter++
            }
        }
        finally
        {
            $peReader.Dispose()
        }
    }
    finally
    {
        $assemblyFileStream.Dispose()
    }
}
else
{
    #PowerShell 5.1 (.NET Framework)
    #Uses the reflection-only load context.
    #The CLR guarantees no code from the assembly can execute in this context
    #No static constructors, no module initializers, only metadata/resources are accessible
    try
    {
        $asm = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($fullPath)
    }
    catch [System.BadImageFormatException]
    {
        throw "'$AssemblyPath' has no CLR metadata. This is not a managed assembly."
    }

    $resourceNames = $asm.GetManifestResourceNames()

    foreach ($name in $resourceNames)
    {
        $stream = $asm.GetManifestResourceStream($name)
        try
        {
            $ms = [System.IO.MemoryStream]::new()
            try
            {
                $stream.CopyTo($ms)
                $buffer = $ms.ToArray()
                Save-Resource -Name $name -Buffer $buffer -OutputDir $OutputDir
                $counter++
            }
            finally
            {
                $ms.Dispose()
            }
        }
        finally
        {
            $stream.Dispose()
        }
    }
}

if ($counter -eq 0)
{
    Write-Host "No embedded resources found in $AssemblyPath"
}
else
{
    Write-Host "`nDone. Extracted $counter resource(s) to: $OutputDir"
}