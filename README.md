<!-- This is for jumping back to the top of the page -->
<a id="readme-top"></a>

<!-- Project Badges -->
<div align="center">

  [![OS: Windows][os-windows-shield]][latest-release-url]
  [![OS: Linux][os-linux-shield]][latest-release-url]
  [![Latest Release][github-release-shield]][latest-release-url]
  <br>
  [![Project License][github-license-shield]][github-license-url]
  [![Project Forks][github-forks-shield]][github-forks-url]
  [![Project Contributors][github-contributors-shield]][github-contributors-url]
  [![Project Last Commit][github-lastcommit-shield]][github-lastcommit-url]
  [![Project Total Downloads][github-downloads-shield]][latest-release-url]
  <br>
  [![PSScript Analyzer Workflow][github-workflows-psscriptanalyzer-shield]][github-psscriptanalyzer-url]
  [![Cross-platform PowerShell Tests Workflow][github-workflows-crossplatformtests-shield]][github-crossplatformtests-url]
  [![Executable Building][github-workflows-exebuilding-shield]][github-exebuilding-url]

</div>

<!-- Project Header -->
<div align="center">

  <h1>💣 Hellbomb Script 💣</h1>

  <p>
    A troubleshooting PowerShell script for <a href="https://store.steampowered.com/app/553850/HELLDIVERS_2/">Helldivers 2</a>
  </p>

  <p>
  <!-- TODO: change these HREF links to use the same system as the shields -->
    <a href="#getting-started"><strong>Download »</strong></a>
    &middot;
    <a href="https://github.com/helldivers2fixes/HellbombScript/issues/new?labels=bug">Report Bug</a>
    &middot;
    <a href="https://github.com/helldivers2fixes/HellbombScript/issues/new?labels=enhancement">Request Feature</a>
  </p>

</div>

<!-- Table of Contents -->
<details open>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#windows">Windows</a></li>
        <li><a href="#linux-alpha">Linux (Alpha)</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
    </li>
    <li><a href="#security">Security</a></li>
    <li><a href="#screenshots">Screenshots</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>


## Getting Started

> ⚠️ **Before you run anything**, especially with Admin/Root privileges: Know what you're downloading and how to validate it's safety. See the [Security](#security) section below for how we sign and verify releases of this project.

### Windows

Pick whichever option you're most comfortable with. (They fold down!)

<!-- Option 1 -->
<details>
  <summary><strong>Option 1: EXE (Recommended)</strong></summary>

  1. [Download][latest-release-url] the latest **EXE**.
  2. Right click the EXE → **Properties** → Check **Unblock** → **OK**.
    ![Unblock EXE properties dialog][unblock-executable-image]
  3. Run the EXE.
  4. Head to [Usage](#usage) for instructions on how to use the tool.
</details>

<!-- Option 2 -->
<details>
  <summary><strong>Option 2: Terminal (Semi-automated)</strong></summary>

  1. Open **Terminal (Admin)** or **PowerShell (Admin)**: Press `Windows Key` + `X`, then choose the admin option.
  2. Copy, paste, and run one of the commands below.

  **Stable release (Recommended):**
  ```powershell
  Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/tags/v4.1/Hellbomb%20Script.ps1 | Invoke-Expression
  ```

  **Bleeding-edge** (latest features but may be incomplete or unstable):
  ```powershell
  Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/heads/main/Hellbomb%20Script.ps1 | Invoke-Expression
  ```

  > 💡 ***Always*** **understand the commands and read through the scripts you are running.** This command downloads and executes the script in one step. To inspect it first, paste the raw URL into your browser and read it there.

</details>

<!-- Option 3 -->
<details>
  <summary><strong>Option 3: Copy and paste (Manual)</strong></summary>

  1. Open **Terminal (Admin)** or **PowerShell (Admin)**: Press `Windows Key` + `X`, then choose the admin option.
  2. Open [the script file][github-script-url] in a new tab so these instructions stay open.
  3. Click the copy button in the top right of the script view to copy the whole thing.
  ![Copy script button][copy-raw-image]

  4. Paste into the terminal with `Ctrl` + `V` (right-click paste can cause errors).
  5. Acknowledge the warning prompt and choose **Paste Anyway**.
  6. Press `Enter` (possibly more than once) until the script runs and the menu appears.

  >We do not recommend this method unless there is a reason why #1 or #2 cannot be used

</details>

### Linux (Alpha)

Supported on Arch Linux and CachyOS. Not all features are available yet.

```bash
sudo paru -S powershell-bin   # Install PowerShell Core
pwsh                          # Launch PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/heads/main/Hellbomb%20Script.ps1 | Invoke-Expression
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

Start by pressing `Enter` to run the default option (**H**), or press **H** yourself. Read through the full output for anything flagged `[FAIL]` or that looks off, or share the results with someone else to read. Most problems get caught here.

Once you've run **H**, use the table below if you still have a specific issue.

### Main Menu Hotkeys

| Key | Opens/Runs |
|---|---|
| `H` | HD2 Status Checks |
| `C` | Clear Data Options (Sub-Menu) |
| `G` | Graphics Options (Sub-Menu) |
| `N` | Network Options (Sub-Menu) |
| `A` | Audio Options (Sub-Menu) |
| `R` | Reset/Toggle Options (Sub-Menu) |
---

<details>
  <summary><strong>Clear Data Options (C)</strong></summary>

  | Key | Opens |
  |---|---|
  | `C` | Clear Settings (AppData) |
  | `M` | Steam Cloud |
  | `Z` | Hostability Key |
  | `Q` | Quick Mod Removal |
  | `B` | Back (Return to the previous menu) |
  ---
</details>

<details>
  <summary><strong>Graphics Options (G)</strong></summary>

  | Key | Opens |
  |---|---|
  | `P` | Select Correct GPU |
  | `O` | Fullscreen Optimizations Toggle |
  | `B` | Back (Return to the previous menu) |
  ---
</details>

<details>
  <summary><strong>Network Options (N)</strong></summary>

  | Key | Opens |
  |---|---|
  | `W` | Wi-Fi LAN Test (Windows Only) |
  | `T` | NAT Test (Windows Only) |
  | `B` | Back (Return to the previous menu) |
  ---
</details>

<details>
  <summary><strong>Audio Options (A)</strong></summary>

  | Key | Opens |
  |---|---|
  | `B` | Toggle Bluetooth Telephony Service (Windows Only) |
  | `T` | NAT Test (Windows Only) |
  | `B` | Back (Return to the previous menu) (Linux Only) |
  ---
</details>

<details>
  <summary><strong>Reset/Toggle Options (R)</strong></summary>

  | Key | Opens |
  |---|---|
  | `G` | GameGuard Reinstall (Windows Only) |
  | `S` | Steam Reset (Windows Only) |
  | `U` | Uninstall VC++ Redists (Windows Only) |
  | `I` | Reinstall VC++ Redists (Windows Only) |
  | `D` | Disable/Enable gameInput Service (Toggle) (Windows Only) |
  | `B` | Back (Return to the previous menu) |
  ---
</details>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security

We want you to be able to trust this script, and to know how to ensure it is safe. See our full [SECURITY.md][github-security-url] for hashes, links and further instructions, but the short version:

- **Code signing:** The Windows EXE is signed free of charge by **[SignPath](https://signpath.org/)**, with a certificate from the SignPath Foundation. A valid signature confirms the file hasn't been tampered with since it was built.

- **Scanner results:** Every release is checked on VirusTotal and HybridAnalysis. You can check out the results found in the [SECURITY.md][github-security-url].

- **Why Admin is needed:** the script reads firewall rules, installs Microsoft Visual C++ redistributables, and downloads/runs the zip version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID. These actions require administrator permissions to be performed correctly.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Screenshots

Formatting varies by Script version. Yours may look slightly different.

### Main Menu
![Main-Menu-Image]

### Running the HD2 status check (`H`)
![Status-Check-Image]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Contributions are welcome. Fork the repo, make your changes, and open a pull request, or open an issue with the `enhancement` tag if you'd rather flag an idea first.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the MIT License. See the [license][github-license-url] for details.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Acknowledgments

- The Windows version uses **CPU-Z** for some functions. Special thanks to Franck at CPU-Z for granting permission to use it.

  <!-- TODO: Replace with local asset -->
  <img src="https://github.com/user-attachments/assets/dc21811d-b124-4962-bf1f-773b45d5b69b" width="150" alt="CPU-Z logo">

- Code signing courtesy of **[SignPath](https://signpath.org/)**, certificate by SignPath Foundation.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!--###################################################################-->
<!-- Markdown links and images -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
<!--###################################################################-->

<!-- shields/badges -->
[os-windows-shield]: https://img.shields.io/badge/OS-Windows-blue
[os-linux-shield]: https://img.shields.io/badge/OS-Linux-green
[github-release-shield]: https://img.shields.io/github/v/release/helldivers2fixes/HellbombScript?include_prereleases&sort=date&display_name=release
[github-license-shield]: https://img.shields.io/github/license/helldivers2fixes/HellbombScript
[github-forks-shield]: https://img.shields.io/github/forks/helldivers2fixes/HellbombScript
[github-contributors-shield]: https://img.shields.io/github/contributors/helldivers2fixes/HellbombScript
[github-lastcommit-shield]: https://img.shields.io/github/last-commit/helldivers2fixes/HellbombScript
[github-downloads-shield]: https://img.shields.io/github/downloads/helldivers2fixes/HellbombScript/total
[github-workflows-psscriptanalyzer-shield]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/powershell.yml/badge.svg
[github-workflows-crossplatformtests-shield]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/TestSuiteAction.yml/badge.svg?branch=main
[github-workflows-exebuilding-shield]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/ps2exe.yml/badge.svg


<!-- links -->
[latest-release-url]: https://github.com/helldivers2fixes/HellbombScript/releases/latest
[github-license-url]: https://github.com/helldivers2fixes/HellbombScript?tab=MIT-1-ov-file
[github-contributors-url]: https://github.com/helldivers2fixes/HellbombScript/graphs/contributors
[github-forks-url]: https://github.com/helldivers2fixes/HellbombScript/forks
[github-lastcommit-url]: https://github.com/helldivers2fixes/HellbombScript/commits/main/
[github-psscriptanalyzer-url]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/powershell.yml
[github-crossplatformtests-url]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/TestSuiteAction.yml
[github-exebuilding-url]: https://github.com/helldivers2fixes/HellbombScript/actions/workflows/ps2exe.yml
[github-script-url]: https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1
[github-security-url]: https://github.com/helldivers2fixes/HellbombScript/blob/main/SECURITY.MD

<!-- images -->
[unblock-executable-image]: assets/unblock-executable.png
[copy-raw-image]: assets/copy-raw.png
[main-menu-image]: assets/main-menu.png
[status-check-image]: assets/status-check.gif