package workflowpolicy

import "testing"

func TestReleaseActionsPinnedToFullSHA(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{name: "build-android", path: ".github/workflows/build-android.yml"},
		{name: "build-linux", path: ".github/workflows/build-linux.yml"},
		{name: "build-macos", path: ".github/workflows/build-macos.yml"},
		{name: "build-windows", path: ".github/workflows/build-windows.yml"},
		{name: "build-snapcraft", path: ".github/workflows/build-snapcraft.yml"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := mustReadWorkflow(t, tc.path)
			mustMatch(t, content, `softprops/action-gh-release@[0-9a-f]{40}`)
		})
	}
}

func TestBuildPermissionsStayLeastPrivilege(t *testing.T) {
	buildAndroid := mustReadWorkflow(t, ".github/workflows/build-android.yml")
	mustContain(t, buildAndroid, "permissions:\n  contents: read")
	mustMatch(t, buildAndroid, `(?s)\n  build:\n(?:.*\n)*?    permissions:\n      contents: read\n`)
	mustMatch(t, buildAndroid, `(?s)\n  release:\n(?:.*\n)*?    permissions:\n      contents: write\n`)

	buildLinux := mustReadWorkflow(t, ".github/workflows/build-linux.yml")
	mustContain(t, buildLinux, "permissions:\n  contents: read")
	mustContain(t, buildLinux, "release:\n    needs: build\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write")

	buildMacOS := mustReadWorkflow(t, ".github/workflows/build-macos.yml")
	mustContain(t, buildMacOS, "permissions:\n  contents: read")
	mustMatch(t, buildMacOS, `(?s)\n  build:\n(?:.*\n)*?    permissions:\n      contents: read\n`)
	mustMatch(t, buildMacOS, `(?s)\n  release:\n(?:.*\n)*?    permissions:\n      contents: write\n`)

	buildWindows := mustReadWorkflow(t, ".github/workflows/build-windows.yml")
	mustContain(t, buildWindows, "permissions:\n  contents: read")
	mustContain(t, buildWindows, "build:\n    runs-on: windows-2025\n    permissions:\n      contents: read")
	mustContain(t, buildWindows, "release:\n    needs: build\n    runs-on: windows-2025\n    permissions:\n      contents: write")

	buildSnapcraft := mustReadWorkflow(t, ".github/workflows/build-snapcraft.yml")
	mustContain(t, buildSnapcraft, "permissions:\n  contents: read")
	mustContain(t, buildSnapcraft, "build-snapcraft:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read")
	mustContain(t, buildSnapcraft, "release:\n    needs: build-snapcraft\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write")
}

func TestLinuxUPXDownloadsRemainChecksumGated(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-linux.yml",
		".github/workflows/pr-test-build-linux.yml",
	} {
		content := mustReadWorkflow(t, path)
		mustContain(t, content, "upx_sha256:")
		mustContain(t, content, "sha256sum --check --strict --status")
	}
}

func TestLinuxDebPackagingDoesNotUseExternalScaffold(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-linux.yml",
		".github/workflows/pr-test-build-linux.yml",
	} {
		content := mustReadWorkflow(t, path)
		mustNotContain(t, content, "github.com/user-attachments/files/21703014/Picocrypt-NG.zip")
		mustContain(t, content, `install -m 0644 src/internal/ui/key.png`)
		mustContain(t, content, `cat > "$package_root/DEBIAN/control"`)
	}
}

func TestSnapcraftActionPinnedToFullSHA(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-snapcraft.yml")
	mustMatch(t, content, `snapcore/action-build@[0-9a-f]{40}`)
}

func TestAndroidPRWorkflowStaysFastAndCompileFocused(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/pr-test-build-android.yml")
	mustContain(t, content, "Run Unit Tests")
	mustContain(t, content, "./gradlew test")
	mustContain(t, content, ":app:compileDebugAndroidTestKotlin")
	mustContain(t, content, ":app:assembleDebugAndroidTest")
	mustNotContain(t, content, "ReactiveCircus/android-emulator-runner@")
	mustNotContain(t, content, "connectedDebugAndroidTest")
}

func TestAndroidReleaseWorkflowKeepsSigningSecretsOutOfBuildJob(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-android.yml")

	buildSection := mustExtractSection(t, content, `(?s)\n  build:\n(.*?)\n  release:\n`)
	mustContain(t, buildSection, "Build Go Mobile AAR")
	mustContain(t, buildSection, "./gradlew test")
	mustNotContain(t, buildSection, "ANDROID_KEYSTORE_BASE64")
	mustNotContain(t, buildSection, "Build Signed Release APK")

	releaseSection := mustExtractSection(t, content, `(?s)\n  release:\n(.*)$`)
	mustContain(t, releaseSection, "ANDROID_KEYSTORE_BASE64")
	mustContain(t, releaseSection, "Build Signed Release APK")
	mustContain(t, releaseSection, "actions/download-artifact@v8")
}

func TestAndroidInstrumentedWorkflowIsManualAndPinned(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/android-instrumented.yml")
	mustContain(t, content, "workflow_dispatch:")
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustContain(t, content, "connectedDebugAndroidTest")
	mustContain(t, content, "PasswordCardTest")
	mustContain(t, content, "ProgressCardTest")
	mustNotContain(t, content, "connectedDebugAndroidTest \\")
	mustContain(t, content, "cd android && ./gradlew connectedDebugAndroidTest")
}

func TestWindowsLegacyPRWorkflowIsCLIOnly(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/pr-test-build-windows-legacy.yml")
	mustContain(t, content, "Picocrypt-NG-cli-Legacy.exe")
	mustContain(t, content, "Build CLI-only legacy binary")
	mustNotContain(t, content, "Build GUI with GLES")
	mustNotContain(t, content, "Add icon, manifest, and version info")
	mustNotContain(t, content, "Mesa3D")
}

func TestWindowsLegacyReleaseWorkflowIsCLIOnly(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-windows-legacy.yml")
	mustContain(t, content, "Picocrypt-NG-cli-Legacy.exe")
	mustContain(t, content, "Build CLI-only legacy binary")
	mustNotContain(t, content, "Build GUI with GLES")
	mustNotContain(t, content, "Add icon, manifest, and version info")
	mustNotContain(t, content, "Mesa3D")
}

func TestWindowsLegacyWorkflowsCacheLegacyGo(t *testing.T) {
	for _, path := range []string{
		".github/workflows/pr-test-build-windows-legacy.yml",
		".github/workflows/build-windows-legacy.yml",
	} {
		content := mustReadWorkflow(t, path)
		mustContain(t, content, "actions/cache@v4")
		mustContain(t, content, "C:\\go-legacy")
	}
}
