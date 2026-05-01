# v2.09
<ul>
	<li>✓ <strong>File associations</strong>: double-click <code>.pcv</code> files to open Picocrypt NG in decrypt mode on Windows / macOS / Linux</li>
	<li>✓ Linux: <code>.deb</code> installs MIME XML + <code>.desktop</code> + AppStream metainfo (Nautilus, Dolphin); Snap advertises handler (host MIME limited per snapd RFE #6467); Flatpak via Flathub manifest</li>
	<li>✓ macOS: <code>.app</code> bundle declares UTI <code>io.github.picocryptng.pcv</code> + Apple Events <code>kAEOpenDocuments</code> handler (Finder cold-launch routes paths to decrypt mode)</li>
	<li>✓ Windows: NSIS installer (<code>Picocrypt-NG-Setup.exe</code>) writes ProgID + registry associations alongside existing portable <code>.exe</code></li>
	<li>✓ Windows: <code>Picocrypt-NG.exe</code> (portable) renamed to <code>Picocrypt-NG-portable.exe</code>; new <code>Picocrypt-NG-Setup.exe</code> ships in parallel</li>
	<li>✓ Cross-platform <code>application/x-pcv</code> MIME type canonicalized in <code>dist/mime/application-x-pcv.xml</code></li>
	<li>✓ File-type icon: <code>images/pcv-icon.svg</code> + 6 PNG renditions (16/32/48/64/128/256) + multi-resolution <code>.ico</code></li>
</ul>

# v2.08
<ul>
	<li>✓ Added Linux ARM64 build artifacts for both GUI and CLI in CI/release pipelines</li>
	<li>✓ Updated Linux workflows to build/test amd64 and arm64 variants on architecture-specific runners</li>
	<li>✓ Updated UPX from v5.0.2 to v5.1.0 across Linux and Windows build workflows</li>
</ul>

# v2.07
<ul>
	<li>✓ Flathub-only packaging release (no application feature changes)</li>
	<li>✓ Added the current Flatpak launcher script for backend selection in Flathub builds</li>
	<li>✓ Aligned Flathub packaging assets and cleaned up Flatpak/AppStream metadata</li>
</ul>

# v2.06
<ul>
	<li>✓ Updated Flatpak app ID to <code>io.github.picocrypt_ng.Picocrypt-NG</code> for Flathub naming compliance</li>
	<li>✓ Renamed Flatpak desktop/metainfo files to the underscore app ID variant</li>
	<li>✓ Expanded Flatpak metainfo with full app description and release entries for v2.01-v2.06</li>
	<li>✓ Updated Flatpak metadata links and IDs for AppStream validation compatibility</li>
</ul>

# v2.05
<ul>
	<li>✓ Stdin/stdout streaming support (<code>-i -</code> and <code>-o -</code>) for pipeline automation</li>
	<li>✓ Fixed data race in signal handler using atomic pointer</li>
	<li>✓ Improved buffer security: zero-page copy for plaintext safety, SecureZero for keyfile buffers</li>
	<li>✓ Better error handling: display errors before exit, handle EOF in interactive input</li>
	<li>✓ Fixed test compatibility on Windows (binary naming, file permissions)</li>
</ul>

# v2.04
<ul>
	<li>✓ Added comprehensive CLI documentation (CLI.md)</li>
	<li>✓ CLI-only build mode: compile with <code>-tags cli</code> for headless servers and containers</li>
	<li>✓ Full CLI feature parity with GUI for all encryption operations</li>
	<li>✓ Password stdin support (<code>-P</code>) for secure scripting and automation</li>
	<li>✓ Glob pattern expansion for batch file encryption</li>
	<li>✓ Smart split volume auto-detection during decryption</li>
	<li>✓ Thread-safe progress reporting with ETA display</li>
	<li>✓ Graceful signal handling (Ctrl+C) with proper cleanup</li>
	<li>✓ Fixed warning text readability by changing yellow color to dark amber for better contrast</li>
	<li>✓ Hide "Confirm password" field in decrypt mode (only needed for encryption)</li>
</ul>

# v2.03
<ul>
	<li>✓ Enhanced file extraction and compression handling with automatic directory creation</li>
	<li>✓ Added auto-toggling of .zip suffix in output filenames based on compression state</li>
	<li>✓ Improved single file compression support with proper file handling and naming conventions</li>
	<li>✓ Enhanced UI with bold labels for better visual hierarchy</li>
	<li>✓ Automatically clear input fields (password, confirm password, comments) upon operation completion</li>
	<li>✓ Improved theme colors and sizes for better readability and contrast</li>
	<li>✓ Added resource management documentation explaining manual file handle closing pattern</li>
</ul>

# v2.02
<ul>
	<li>✓ Refactored to modular package structure (crypto, header, volume, etc.)</li>
	<li>✓ Switched from giu to Fyne UI toolkit</li>
	<li>✓ Added mobile support (Android)</li>
	<li>✓ v2 header format with HMAC-SHA3-512 authentication (audit recommendation PCC-001)</li>
	<li>✓ Backward compatible with v1.x volumes</li>
	<li>✓ Added project documentation (ARCHITECTURE.md, API.md, CONTRIBUTING.md)</li>
</ul>

# v2.00 (Released 08/07/2025)
<ul>
	<li>✓ First release in new Picocrypt-NG organization!</li>
</ul>

# v1.49 (Released 08/03/2025)
<ul>
	<li>✓ Update macOS icon to fit better</li>
	<li>✓ Added support for Cyrillic characters (https://github.com/Picocrypt/giu/pull/1), thanks <a href="https://github.com/Retengart">@Retengart</a></li>
	<li>✓ upx Linux binary in addition to Windows, update upx version for Windows</li>
</ul>

# v1.48 (Released 04/18/2025)
<ul>
	<li>✓ Allow pressing 'Enter' key to press Start/Process button</li>
	<li>✓ Update "Encrypt" button to "Zip and Encrypt" if multiple files</li>
	<li>✓ Give user estimated required free disk space in status label</li>
	<li>✓ Encrypt previously unencrypted temporary zip files</li>
	<li>✓ Add `.incomplete` to filenames while work is in progress</li>
	<li>✓ Use `encrypted-*.zip.pcv` output name instead of `Encrypted.zip.pcv`</li>
	<li>✓ Use 0700 permissions when auto unzipping and creating folders</li>
	<li>✓ Handle many more errors in the code where they were ignored previously</li>
</ul>

# v1.47 (Released 02/19/2025)
<ul>
	<li>✓ No code changes, just build on newly released Go 1.24</li>
	<li>✓ Reintroduce the Windows installer made using Inno Setup</li>
</ul>

# v1.46 (Released 01/29/2025)
<ul>
	<li>✓ Added Picocrypt version to the window title</li>
	<li>✓ Added ability to automatically unzip archives upon decryption</li>
</ul>

# v1.45 (Released 12/05/2024)
<ul>
	<li>✓ Bumped GitHub Actions Ubuntu 22 -> 24 and macOS 14 -> 15</li>
</ul>

# v1.44 (Released 11/09/2024)
<ul>
	<li>✓ No changes, just updated dependencies</li>
</ul>

# v1.43 (Released 09/11/2024)
<ul>
	<li>✓ No changes, just updated dependencies</li>
</ul>

# v1.42 (Released 09/03/2024)
<ul>
	<li>✓ <strong>Security audit by Radically Open Security has concluded! No major security issues were found🥳</strong></li>
	<li>✓ Panic if crypto/rand.Read fails</li>
	<li>✓ Assume host machine is trusted, make notes in documentation accordingly</li>
	<li>✓ Handle edge cases regarding comments</li>
</ul>

# v1.41 (Released 08/30/2024)
<ul>
	<li>✓ Move all external packages to under Picocrypt organization</li>
</ul>

# v1.40 (Released 08/10/2024)
<ul>
	<li>✓ Allow "Open with Picocrypt" to work; you can drop files and folders onto the executable now!</li>
</ul>

# v1.39 (Released 08/07/2024)
<ul>
	<li>✓ Disable comments if deniability is enabled</li>
</ul>

# v1.38 (Released 08/03/2024)
<ul>
	<li>✓ Remove periods from the end of labels</li>
</ul>

# v1.35 - v1.37 (Released 07/08/2024)
<ul>
	<li>✓ Various small releases to get workflows running and automated builds released</li>
	<li>✓ Reduce keyfile generator's output size from 1 KiB -> 32 bytes since 32 bytes is enough</li>
</ul>

# v1.34 (Released 04/29/2024)
<ul>
	<li>✓ New CLI with support for files, folders, globs, paranoid mode, and Reed-Solomon</li>
	<li>✓ Migrate github.com/HACKERALERT/crypto back to golang.org/x/crypto</li>
	<li>✓ Distribute raw Linux binary instead of AppImage for better portability</li>
	<li>✓ Distribute macOS binaries for both Intel and Apple silicon</li>
</ul>

# v1.33 (Released 06/27/2023)
<ul>
	<li>✓ Add tooltip warning that comments are not encrypted (#164)</li>
	<li>✓ Hash keyfiles in chunks to reduce memory usage (#168)</li>
	<li>✓ Prevent using identical keyfiles under different filenames (#170)</li>
</ul>

# v1.32 (Released 04/28/2023)
<ul>
	<li>✓ Added a command-line interface</li>
	<li>✓ Use Debian 11 as the base for the AppImage instead of Debian 10</li>
	<li>✓ Include software rendering DLLs in the Paranoid Pack for future proofing</li>
	<li>✓ Add plausible deniability and recursive encryption</li>
	<li>✓ Added an installer for Windows (made using Inno Setup)</li>
</ul>

# v1.31 (Released 11/18/2022)
<ul>
	<li>✓ Force software OpenGL rendering on macOS</li>
	<li>✓ Use native clipboard APIs instead of external package (removes need for xclip)</li>
	<li>✓ Revert using system temporary folder due to size issues</li>
</ul>

# v1.30 (Released 09/24/2022)
<ul>
	<li>✓ Improve tooltip word choice</li>
	<li>✓ Add FAQ to README</li>
	<li>✓ Fix scaling issue when moving between monitors with different DPIs (on Windows)</li>
	<li>✓ Strip periods from custom output filename to prevent file extension problems</li>
	<li>✓ Minor tweaks to keyfile modal</li>
	<li>✓ Use temporary .zip file to prevent overwriting when encrypting</li>
	<li>✓ Check if files already exist when recombining and splitting to prevent overwriting</li>
	<li>✓ Show ".*" in the output box if splitting</li>
	<li>✓ Skip temporary and inaccessible files when combining/compressing</li>
	<li>✓ Improve file scanning performance by precomputing total size</li>
	<li>✓ Stability improvements and fixes for edge cases</li>
	<li>✓ Check for clipboard support on Linux</li>
</ul>

# v1.29 (Released 05/23/2022)
<ul>
	<li>✓ Review/improve Internals.md</li>
	<li>✓ Add option to compress when encrypting a single file</li>
	<li>✓ Check for errors when not enough disk space</li>
	<li>✓ Show MiB/GiB instead of M/G in the input label to prevent confusion</li>
	<li>✓ Minor consistency improvements</li>
</ul>

# v1.28 (Released 05/16/2022)
<ul>
	<li>✓ Fix bug when decrypting a splitted volume with a custom output name and "Delete files" selected</li>
	<li>✓ Improve responsiveness of cancel button (instant cancel when pressed instead of delays)</li>
	<li>✓ Software OpenGL rendering on Windows (for Windows on ARM compatibility and older hardware)</li>
	<li>✓ Progress, speed, and ETA for combining/compressing files, recombining files, and splitting files</li>
	<li>✓ Improve overall IO performance</li>
	<li>✓ Much smoother Reed-Solomon decryption flow, slightly better performance</li>
	<li>✓ Major code cleanups and organizing</li>
	<li>✓ <i>Much better</i> file permission handling</li>
	<li>✓ Numerous minor fixes and improvements</li>
	<li>✓ Improve Reed-Solomon performance (only rebuild data if corruption is detected)</li>
	<li>✓ `gofmt` and `go mod tidy` all dependencies</li>
	<li>✓ Fix bad pointer issue when running with `-race`</li>
	<li>✓ Fix focus bug where input boxes are not cleared if they are focused when file is dropped</li>
	<li>✓ Fix bug on Windows where copying from the password field using Ctrl+C and then pasting with the "Paste" button would cause a crash</li>
	<li>✓ Make sure at least one password characters category is checked when generating</li>
	<li>✓ Use `desktop-file-validate` to find and remove deprecated fields and fix invalid ones in the .desktop for .deb and AppImage</li>
	<li>✓ .deb and AppImage optimizations, reliability improvements</li>
	<li>✓ Snapcraft uses software OpenGL rendering as well now</li>
	<li>✓ Statically linked libc6, etc. for best cross-platform compatibility for Snapcraft</li>
	<li>✓ Added NO_AT_BRIDGE=1 to Snapcraft to fix an issue on Arch Linux (#75)</li>
	<li>✓ Clean up unnecessary files in dependencies</li>
	<li>✓ Sign executables with OpenPGP</li>
</ul>

# v1.27 (Released 05/02/2022)
<ul>
	<li>✓ Input validation for split size</li>
	<li>✓ Ability to split into a custom number of total chunks in addition to by size</li>
	<li>✓ Fix issue with long comments</li>
	<li>✓ Deprecate Snapcraft and provide a .deb and AppImage instead</li>
</ul>

# v1.26 (Released 04/18/2022)
<ul>
	<li>✓ Fix a race condition</li>
	<li>✓ Fix invalid pointer crash when decrypting files >256GB</li>
	<li>✓ UI improvements and tweaks</li>
	<li>✓ Fix crash on Windows when saving to the root directory of a drive</li>
	<li>✓ Max file size limit removed! Picocrypt can now encrypt files of unlimited size instead of being capped at 256 GiB</li>
	<li>✓ Shows total input size along with input label</li>
	<li>✓ Update to GLFW 3.3.6 for better stability</li>
</ul>

# v1.25 (Released 04/13/2022)
<ul>
	<li>✓ Improve Internals documentation (header format, etc.)</li>
	<li>✓ Save as and keyfile file dialog now opens in the same directory as dropped files</li>
	<li>✓ Improvements for long file names</li>
	<li>✓ Minor UI improvements and fixes</li>
</ul>

# v1.24 (Released 04/02/2022)
<ul>
	<li>✓ Fixed layout bug that allowed scrolling within window</li>
	<li>✓ Optimize dependencies</li>
	<li>✓ Numerous code and UI optimizations, including better comments</li>
	<li>✓ Keyfile modal will recenter automatically upon dropping a keyfile</li>
	<li>✓ Fix modals moving around randomly when open and closed numerous times</li>
	<li>✓ Fixed: Progressbar modal moves around weirdly sometimes</li>
	<li>✓ Better error handling</li>
	<li>✓ Show compression speed and percentage</li>
	<li>✓ Smoothen splitting file and recombing file progress bars</li>
	<li>✓ Finish adding tooltips</li>
</ul>

# v1.23 (Released 03/19/2022)
<ul>
	<li>✓ Removed the checksum generator to get back on track with original Picocrypt ideology</li>
	<li>✓ Cleaned up and optimized code</li>
	<li>✓ Compiled with MinGW GCC11 instead of TDM-GCC, Go 1.18 instead of Go 1.17</li>
	<li>✓ Picocrypt no longer checks for new versions, so no network requests are ever made</li>
</ul>

# v1.22 (Released 12/22/2021)
<ul>
	<li>✓ Remove fast mode, as a change for the normal mode will make fast mode obselete</li>
	<li>✓ For normal mode, change HMAC-SHA3 to a keyed Blake2b</li>
</ul>

# v1.21 (Released 11/19/2021)
<ul>
	<li>✓ Remove file shredder because it won't be very effective in the future</li>
	<li>✓ Fix minor temporary file bug</li>
	<li>✓ Improve decryption UI</li>
</ul>

# v1.20 (Released 11/12/2021)
<ul>
	<li>✓ Fix keyfile modal UI layout</li>
	<li>✓ Fix keyfile modal typo</li>
	<li>✓ Fix minor keyfile bug</li>
	<li>✓ Improve shredding window layout</li>
	<li>✓ Fork all dependencies and recursive dependencies into "offline" repos for hardening and better stability</li>
	<li>✓ Fix UI scaling issues</li>
	<li>✓ Fix high DPI layout issues</li>
	<li>✓ Optimize zip compressor</li>
</ul>

# v1.19 (Released 09/26/2021)
<ul>
	<li>✓ UI scaling hotfix</li>
</ul>

# v1.18 (Released 09/24/2021)
<ul>
	<li>✓ Make UI more consistent (minor DPI issues)</li>
	<li>✓ Fix crashing when OS denies permission to access file</li>
	<li>✓ Fixed bug where file object was not closed properly</li>
	<li>✓ Encryption/decryption file naming and extension bugs</li>
	<li>✓ Many fixes, optimizations, and linting</li>
</ul>

# v1.17 (Released 09/04/2021)
<ul>
	<li>✓ (abandoned due to UI issues with ASCII codes >128) Extended ASCII set in password generator</li>
	<li>✓ Tooltips for all advanced options</li>
	<li>✓ Localization support (use system default where possible)</li>
	<li>✓ Auto detect system locale, fallback to English</li>
	<li>✓ Fix ETA negative number bug</li>
	<li>✓ Add clear button to password field</li>
	<li>✓ Multiple keyfiles support and DND</li>
	<li>✓ Option to require specific keyfile order</li>
	<li>✓ Keyfile generator</li>
	<li>✓ Bug: Red error label shown in main window during successful decryption after selecting incorrect keyfiles</li>
	<li>✓ Prevent duplicate keyfile</li>
	<li>✓ Add a select keyfile button</li>
	<li>✓ Make sure only one of "Fast mode" and "Paranoid mode" can be enabled</li>
	<li>✓ Fix bug where metadata says "read-only", but the textbox is modifiable</li>
	<li>✓ Add option to delete encrypted files after decryption</li>
</ul>
<strong>Note: v1.17 will be incompatible with all previous releases!</strong>

# v1.16 (Released 08/11/2021)
<ul>
	<li>✓ Fixed bug when entering a wrong password when decrypting a splitted file</li>
	<li>✓ Fixed bug where an existing file is delete when a wrong password is used</li>
	<li>✓ The password generator is now customizable</li>
	<li>✓ Make keyfile support more reliable (keyfile now out of Beta)</li>
	<li>✓ Fix keyfile user flow issue</li>
	<li>✓ Bug fixes</li>
	<li>✓ UI fixes improvements</li>
</ul>

# v1.15 (Released 08/09/2021)
<ul>
	<li>✓ Add cancel button to file shredder and custom number of passes</li>
	<li>✓ Password generator</li>
	<li>✓ Make password strength circle start at top</li>
	<li>✓ Fix shredder UI bugs</li>
</ul>

# v1.14 (Released 08/07/2021)
<ul>
	<li>✓ Low-severity security fix for the recently discovered partitioning oracle attacks</li>
	<li>✓ Move from Monocypher to Go's standard supplemental ChaCha20 in favour of the latter being stateful</li>
	<li>✓ Add SHA3 (normal mode) and BLAKE2b (fast mode) as HMAC to replace Poly1305 and prevent partitioning oracle attacks</li>
	<li>✓ Removed ~100 lines of unnecessary code now that Picocrypt uses Go's ChaCha20 (cleaner and stabler code)</li>
	<li>✓ Added window icons</li>
	<li>✓ Switch to a new Reed-Solomon encoder that automatically corrects errors</li>
	<li>✓ Add a "Paranoid mode", which will use the Serpent cipher in addition to XChaCha20</li>
	<li>✓ Cleaner code with plenty of comments for people taking a look</li>
	<li>✓ Metadata is now Reed-Solomon encoded (everything bit of header data is now RS-encoded for redundancy)</li>
	<li>✓ Reed-Solomon checkbox is now enabled and Reed-Solomon works</li>
	<li>✓ Implemented Dropbox's zxcvbn password strength checker</li>
	<li>✓ Removed paranoid shredding as it is too hard to implement correctly and not cross platform</li>
	<li>✓ Fixed Windows zip extract error notice that doesn't appear in 7-Zip (edit: it was a backslash issue)</li>
	<li>✓ Optional shred temporary files checkbox</li>
	<li>✓ Remove BLAKE3 from the checksum generator tab, as it has no practical use and requires a non-standard library</li>
	<li>✓ Advanced options are shown dynamically depending on whether encrypting or decrypting</li>
	<li>✓ Window closing disabled during encryption/decryption/shredding to prevent leakage of temporary files</li>
	<li>✓ Reduce padding of metadataLength from 10 to 5 (you probably won't type more than 99999 metadata characters)</li>
	<li>✓ Use regex to check if an input file is a valid Picocrypt volume or not during decryption</li>
	<li>✓ Improved user flow as well as fix UI bugs</li>
	<li>✓ Code optimizations</li>
	<li>✓ Many bug fixes/stability improvments</li>
</ul>
<strong>Note: v1.14 will be incompatible with all previous releases!</strong>

# v1.13 (Released 5/29/2021)
<ul>
	<li>✓ Picocrypt has been ported from Python to Go, thus completely rewritten</li>
	<li>✓ Added fast mode, which can achieve ~250MB/s</li>
	<li>✓ Added file shredder and file checksum generator</li>
	<li>✓ Automatically checks for newer versions</li>
	<li>✓ Added file chunking support</li>
</ul>
<strong>Note: v1.13 will be incompatible with all previous releases!</strong>

# v1.12.1 (Released 04/11/2021)
<ul>
	<li>✓ Fixed a bug that caused "Secure wipe" feature to show "Unknown error" when done</li>
</ul>

# v1.12 (Released 04/07/2021)
<ul>
	<li>✓ Beautiful UI</li>
	<li>✓ More than x2 as fast as previous versions</li>
	<li>✓ Add cancel button to cancel encryption/decryption</li>
	<li>✓ (Bug) Delete existing file only if password is correct</li>
	<li>✓ Minor aesthetic fixes</li>
	<li>✓ Complete rewrite from scratch, to ensure reliability and security</li>
	<li>✓ Better anti-corruption (re-defined header format)</li>
	<li>✓ Switch to Argon2d instead Argon2id for better security</li>
	<li>✓ Switch from SHA3 to BLAKE3 for corruption check</li>
	<li>✓ Better user flow</li>
</ul>
<strong>Note: v1.12 will be incompatible with all previous releases!</strong>

# v1.11 (Released 03/23/2021)
<ul>
	<li>✓ Much more secure wipe via <code>sdelete64</code> for Windows, <code>shred</code> for Linux, and <code>rm -P</code> for MacOS</li>
	<li>✓ Much more beautiful UI for macOS</li>
	<li>✓ Robust secure wipe support for drag and dropped files/folders</li>
	<li>✓ Only open input files in read mode, since write mode is unnecessary</li>
	<li>✓ Clean up source code, add better comments</li>
	<li>✓ Drag and drop support (multiple files, a folder, a file and a folder, etc.)</li>
</ul>
