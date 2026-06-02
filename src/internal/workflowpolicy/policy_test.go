package workflowpolicy

import "testing"

func TestReleaseActionsPinnedToFullSHA(t *testing.T) {
	testCases := []struct {
		name string
		path string
		job  string
	}{
		{name: "build-android", path: ".github/workflows/build-android.yml", job: "release"},
		{name: "build-linux", path: ".github/workflows/build-linux.yml", job: "release"},
		{name: "build-macos", path: ".github/workflows/build-macos.yml", job: "release"},
		{name: "build-windows", path: ".github/workflows/build-windows.yml", job: "release"},
		{name: "build-snapcraft", path: ".github/workflows/build-snapcraft.yml", job: "release"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			releaseStep := mustHaveStepUsingPrefix(t, releaseJob, "softprops/action-gh-release@")
			mustMatch(t, releaseStep.Uses, `softprops/action-gh-release@[0-9a-f]{40}`)
		})
	}
}

func TestBuildPermissionsStayLeastPrivilege(t *testing.T) {
	buildAndroid := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	mustPermission(t, buildAndroid.Permissions, "contents", "read")
	mustEffectivePermission(t, buildAndroid, mustJob(t, buildAndroid, "build"), "contents", "read")
	mustPermission(t, mustJob(t, buildAndroid, "release").Permissions, "contents", "write")

	buildLinux := mustReadWorkflowDoc(t, ".github/workflows/build-linux.yml")
	mustPermission(t, buildLinux.Permissions, "contents", "read")
	mustEffectivePermission(t, buildLinux, mustJob(t, buildLinux, "build"), "contents", "read")
	mustEffectivePermission(t, buildLinux, mustJob(t, buildLinux, "release"), "contents", "write")

	buildMacOS := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	mustPermission(t, buildMacOS.Permissions, "contents", "read")
	mustEffectivePermission(t, buildMacOS, mustJob(t, buildMacOS, "build"), "contents", "read")
	mustEffectivePermission(t, buildMacOS, mustJob(t, buildMacOS, "release"), "contents", "write")

	buildWindows := mustReadWorkflowDoc(t, ".github/workflows/build-windows.yml")
	mustPermission(t, buildWindows.Permissions, "contents", "read")
	mustEffectivePermission(t, buildWindows, mustJob(t, buildWindows, "build"), "contents", "read")
	mustEffectivePermission(t, buildWindows, mustJob(t, buildWindows, "release"), "contents", "write")

	buildSnapcraft := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	mustPermission(t, buildSnapcraft.Permissions, "contents", "read")
	mustEffectivePermission(t, buildSnapcraft, mustJob(t, buildSnapcraft, "build-snapcraft"), "contents", "read")
	mustEffectivePermission(t, buildSnapcraft, mustJob(t, buildSnapcraft, "release"), "contents", "write")
}

func TestMacOSReleaseWorkflowInjectsRootVersionIntoBundleMetadata(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	buildJob := mustJob(t, workflow, "build")
	packageStep := mustStepNamed(t, buildJob, "Package as .app in a .dmg")

	mustContain(t, packageStep.Run, `plutil -replace CFBundleShortVersionString -string "$(cat VERSION)"`)
	mustContain(t, packageStep.Run, `plutil -replace CFBundleVersion -string "$(cat VERSION)"`)
}

func TestWindowsReleaseWorkflowPassesRootVersionToNSIS(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-windows.yml")
	buildJob := mustJob(t, workflow, "build")
	nsisStep := mustStepNamed(t, buildJob, "Build NSIS installer")

	mustContainInOrder(t, nsisStep.Run,
		`$version = (Get-Content -Path "VERSION" -Raw).Trim()`,
		`makensis.exe`,
		`"-DVERSION=$version"`,
	)
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
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	buildJob := mustJob(t, workflow, "build-snapcraft")
	buildStep := mustHaveStepUsingPrefix(t, buildJob, "snapcore/action-build@")
	mustMatch(t, buildStep.Uses, `snapcore/action-build@[0-9a-f]{40}`)
}

func TestSnapcraftWorkflowSmokeTestsInstalledSnap(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	buildJob := mustJob(t, workflow, "build-snapcraft")
	smokeStep := mustStepNamed(t, buildJob, "Smoke-test snap command")
	if smokeStep.Env["LANG"] != "C.UTF-8" {
		t.Fatalf("snap smoke-test LANG = %q, want C.UTF-8", smokeStep.Env["LANG"])
	}
	if smokeStep.Env["LC_ALL"] != "C.UTF-8" {
		t.Fatalf("snap smoke-test LC_ALL = %q, want C.UTF-8", smokeStep.Env["LC_ALL"])
	}
	mustContain(t, smokeStep.Run, "sudo snap install --dangerous out/*.snap")
	mustContain(t, smokeStep.Run, "snap run picocrypt-ng --version")
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
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	buildJob := mustJob(t, workflow, "build")
	releaseJob := mustJob(t, workflow, "release")

	mustStepNamed(t, buildJob, "Build Go Mobile AAR")
	mustStepNamed(t, buildJob, "Run Unit Tests")
	mustNotHaveStepNamed(t, buildJob, "Decode Android signing keystore")
	mustNotHaveStepNamed(t, buildJob, "Build Signed Release APK")

	releaseStep := mustStepNamed(t, releaseJob, "Decode Android signing keystore")
	if _, ok := releaseStep.Env["ANDROID_KEYSTORE_BASE64"]; !ok {
		t.Fatal("release keystore decode step should declare ANDROID_KEYSTORE_BASE64")
	}
	mustStepNamed(t, releaseJob, "Build Signed Release APK")
	mustStepUsing(t, releaseJob, "actions/download-artifact@v8")
}

func TestAndroidInstrumentedWorkflowIsManualAndPinned(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/android-instrumented.yml")
	mustContain(t, content, "workflow_dispatch:")
	mustContain(t, content, "test_scope:")
	mustContain(t, content, "default: focused")
	mustContain(t, content, "- focused")
	mustContain(t, content, "- extended")
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustContain(t, content, "connectedDebugAndroidTest")
	mustContain(t, content, "PasswordCardTest")
	mustContain(t, content, "ProgressCardTest")
	mustContain(t, content, "OperationManagerIntegrationTest")
	mustNotContain(t, content, "connectedDebugAndroidTest \\")
	mustContain(t, content, "TEST_CLASSES=")
	mustContain(t, content, "./gradlew connectedDebugAndroidTest")
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
	testCases := []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/pr-test-build-windows-legacy.yml", job: "pr-test-build-windows-legacy"},
		{path: ".github/workflows/build-windows-legacy.yml", job: "build"},
	}

	for _, tc := range testCases {
		workflow := mustReadWorkflowDoc(t, tc.path)
		job := mustJob(t, workflow, tc.job)
		cacheStep := mustStepNamed(t, job, "Cache go-legacy-win7")
		if cacheStep.Uses != "actions/cache@v4" {
			t.Fatalf("cache step uses = %q, want actions/cache@v4", cacheStep.Uses)
		}
		if cacheStep.With["path"] != `C:\go-legacy` {
			t.Fatalf("cache step path = %#v, want C:\\go-legacy", cacheStep.With["path"])
		}
	}
}
