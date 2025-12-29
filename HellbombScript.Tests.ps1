Describe "Hellbomb Script Launch Validation" {
        # This runs before every test in this block
    BeforeAll {
        # Mock UI inputs so the script doesn't hang in CI
        Mock Read-Host { return "Exit" } 
        Mock Pause { return $true }
    }

    It "Should exist on the filesystem" {
        "./Hellbomb Script.ps1" | Should -Exist
    }

    It "Should pass a syntax check (Compilation)" {
        # This checks if the script has any 'broken' code without running the logic
        { 
            $scriptContent = Get-Content "./Hellbomb Script.ps1"
            [scriptblock]::Create($scriptContent) 
        } | Should -Not -Throw
    }

    It "Should be able to get the command metadata" {
        # This ensures PowerShell can 'see' the script as an executable command
        Get-Command "./Hellbomb Script.ps1" | Should -Not -BeNullOrEmpty
    }
}
