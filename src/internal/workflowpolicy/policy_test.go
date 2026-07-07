package workflowpolicy

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStaticChecksWorkflowEnforcesFormatVetLintAndVuln(t *testing.T) {
	const path = ".github/workflows/pr-static-checks.yml"
	workflow := mustReadWorkflowDoc(t, path)

	// Least-privilege, like every other PR workflow.
	mustPermission(t, workflow.Permissions, "contents", "read")

	job := mustJob(t, workflow, "static-checks")

	gofmtStep := mustStepNamed(t, job, "Check formatting (gofmt)")
	mustContain(t, gofmtStep.Run, "gofmt -l")

	vetStep := mustStepNamed(t, job, "Vet")
	mustContain(t, vetStep.Run, "go vet ./...")

	lintStep := mustStepNamed(t, job, "Lint (golangci-lint)")
	mustContain(t, lintStep.Run, "run ./...")
	// golangci-lint must be pinned to an explicit version (the v2 config is
	// version-sensitive); @latest would make CI non-reproducible.
	mustMatch(t, lintStep.Run, `golangci-lint/v2/cmd/golangci-lint@v[0-9]+\.[0-9]+\.[0-9]+`)
	mustNotContain(t, lintStep.Run, "golangci-lint/v2/cmd/golangci-lint@latest")

	vulnStep := mustStepNamed(t, job, "Vulnerability scan (govulncheck)")
	mustContain(t, vulnStep.Run, "govulncheck ./...")

	content := mustReadWorkflow(t, path)
	mustContain(t, content, "pull_request:")
}

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
		{name: "build-windows-legacy", path: ".github/workflows/build-windows-legacy.yml", job: "release"},
		{name: "build-snapcraft", path: ".github/workflows/build-snapcraft.yml", job: "release"},
		{name: "build-appimage", path: ".github/workflows/build-appimage.yml", job: "release"},
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

func TestExternalGitHubActionsPinnedToFullSHAWithVersionComment(t *testing.T) {
	actionRef := regexp.MustCompile(`uses:\s*([^@\s]+)@([0-9a-f]{40})(?:\s+#\s+v[0-9][^\s]*)?$`)
	workflowFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("glob workflows: %v", err)
	}
	actionFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "actions", "*", "action.yml"))
	if err != nil {
		t.Fatalf("glob composite actions: %v", err)
	}

	files := make([]string, 0, len(workflowFiles)+len(actionFiles))
	files = append(files, workflowFiles...)
	files = append(files, actionFiles...)
	for _, absPath := range files {
		relPath, err := filepath.Rel(repoRoot(t), absPath)
		if err != nil {
			t.Fatalf("rel path for %s: %v", absPath, err)
		}
		content := mustReadRepoFile(t, relPath)
		for lineNo, line := range strings.Split(content, "\n") {
			if !strings.Contains(line, "uses:") {
				continue
			}
			if strings.Contains(line, "uses: ./") {
				continue
			}
			if !actionRef.MatchString(strings.TrimSpace(line)) {
				t.Fatalf("%s:%d external action must use a 40-hex SHA and same-line version comment, got %q", relPath, lineNo+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestReleaseJobsRequireMainBranchAndReleaseEnvironment(t *testing.T) {
	testCases := []struct {
		name string
		path string
		job  string
	}{
		{name: "build-android", path: ".github/workflows/build-android.yml", job: "release"},
		{name: "build-appimage", path: ".github/workflows/build-appimage.yml", job: "release"},
		{name: "build-linux", path: ".github/workflows/build-linux.yml", job: "release"},
		{name: "build-macos", path: ".github/workflows/build-macos.yml", job: "release"},
		{name: "build-snapcraft", path: ".github/workflows/build-snapcraft.yml", job: "release"},
		{name: "build-windows", path: ".github/workflows/build-windows.yml", job: "release"},
		{name: "build-windows-legacy", path: ".github/workflows/build-windows-legacy.yml", job: "release"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			if releaseJob.If != "${{ github.ref == 'refs/heads/main' }}" {
				t.Fatalf("release job if = %q, want main branch guard", releaseJob.If)
			}
			if got := releaseEnvironmentName(releaseJob.Environment); got != "release" {
				t.Fatalf("release job environment = %#v, want release", releaseJob.Environment)
			}
		})
	}
}

func TestAppImageSigningSecretsRequireReleaseEnvironment(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	buildJob := mustJob(t, workflow, "build")

	if buildJob.If != "${{ github.ref == 'refs/heads/main' }}" {
		t.Fatalf("AppImage signing build job if = %q, want main branch guard", buildJob.If)
	}
	if got := releaseEnvironmentName(buildJob.Environment); got != "release" {
		t.Fatalf("AppImage signing build job environment = %#v, want release", buildJob.Environment)
	}

	importStep := mustStepNamed(t, buildJob, "Import GPG signing key")
	if _, ok := importStep.Env["GPG_PRIVATE_KEY"]; !ok {
		t.Fatal("AppImage signing build job should keep the GPG private key scoped to its import step")
	}
	buildStep := mustStepNamed(t, buildJob, "Build AppImage")
	if _, ok := buildStep.Env["APPIMAGETOOL_SIGN_PASSPHRASE"]; !ok {
		t.Fatal("AppImage signing build job should keep the AppImage passphrase scoped to its build step")
	}
}

func releaseEnvironmentName(env any) string {
	switch v := env.(type) {
	case string:
		return v
	case map[string]any:
		if name, ok := v["name"].(string); ok {
			return name
		}
	}
	return ""
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

	buildAppImage := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	mustPermission(t, buildAppImage.Permissions, "contents", "read")
	mustEffectivePermission(t, buildAppImage, mustJob(t, buildAppImage, "build"), "contents", "read")
	mustEffectivePermission(t, buildAppImage, mustJob(t, buildAppImage, "release"), "contents", "write")
}

func TestAppImageWorkflowIsPortableSmokeTestedAndPinned(t *testing.T) {
	const path = ".github/workflows/build-appimage.yml"
	workflow := mustReadWorkflowDoc(t, path)
	content := mustReadWorkflow(t, path)

	build := mustJob(t, workflow, "build")

	// Portability floor. AppImage was dropped once "for better portability"
	// (Changelog v1.34); building on the newest runner's glibc reproduces that, so the
	// build job pins the oldest supported runner (ubuntu-22.04, glibc 2.35).
	mustContain(t, content, "runs-on: ubuntu-22.04")

	// Supply chain: the AppImage tooling is fetched at build time, so it must be
	// sha256-pinned AND verified (fail loud), like UPX in build-linux. Asserts that a
	// pin exists and is checked -- not the exact digest -- so a tool bump does not churn
	// this test.
	mustContain(t, content, "linuxdeploy")
	mustContain(t, content, "appimagetool")
	mustMatch(t, content, `[0-9a-f]{64}`)
	mustContain(t, content, "sha256sum")
	mustContain(t, content, "--check")

	// The produced AppImage must be smoke-tested, or a broken bundle (a shared library
	// that fails to resolve) ships silently. --version drives the embedded CLI
	// (cli.Execute), which exits before Fyne/OpenGL init, so it proves every bundled and
	// host-provided library resolves at process start without needing a display.
	smoke := mustStepNamed(t, build, "Smoke test AppImage")
	mustContain(t, smoke.Run, "--version")
	mustContain(t, smoke.Run, ".AppImage")
}

func TestMacOSReleaseWorkflowInjectsRootVersionIntoBundleMetadata(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	buildJob := mustJob(t, workflow, "build")
	packageStep := mustStepNamed(t, buildJob, "Package as .app in a .dmg")

	mustContain(t, packageStep.Run, `plutil -replace CFBundleShortVersionString -string "$(cat VERSION)"`)
	mustContain(t, packageStep.Run, `plutil -replace CFBundleVersion -string "$(cat VERSION)"`)
}

func TestMacOSReleaseWorkflowPublishesCLIFromFlatArtifact(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	buildJob := mustJob(t, workflow, "build")
	releaseJob := mustJob(t, workflow, "release")

	stageStep := mustStepNamed(t, buildJob, "Stage release artifacts")
	mustContain(t, stageStep.Run, "cp Picocrypt-NG.dmg release-staging/")
	mustContain(t, stageStep.Run, "cp src/Picocrypt-NG-cli-macos release-staging/")
	mustContain(t, stageStep.Run, "test -s release-staging/Picocrypt-NG-cli-macos")

	uploadStep := mustStepNamed(t, buildJob, "Upload artifacts")
	if uploadStep.With["path"] != "release-staging/" {
		t.Fatalf("macOS upload artifact path = %#v, want flat release-staging/", uploadStep.With["path"])
	}

	verifyStep := mustStepNamed(t, releaseJob, "Verify artifacts present")
	mustContain(t, verifyStep.Run, "set -euo pipefail")
	mustContain(t, verifyStep.Run, "test -s artifacts/build-macos/Picocrypt-NG-cli-macos")

	releaseStep := mustHaveStepUsingPrefix(t, releaseJob, "softprops/action-gh-release@")
	files, ok := releaseStep.With["files"].(string)
	if !ok {
		t.Fatalf("macOS release files input = %#v, want string", releaseStep.With["files"])
	}
	mustContain(t, files, "artifacts/build-macos/Picocrypt-NG-cli-macos")
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
		t.Run(path, func(t *testing.T) {
			content := mustReadWorkflow(t, path)
			mustNotContain(t, content, "github.com/user-attachments/files/21703014/Picocrypt-NG.zip")
			mustContain(t, content, "librsvg2-bin")
			mustContain(t, content, "xmllint --noout images/key.svg")
			mustContain(t, content, `cat > "$package_root/DEBIAN/control"`)
			mustContain(t, content, `install -d "$package_root/usr/share/icons/hicolor/scalable/apps"`)
			mustContain(t, content, `install -m 0644 images/key.svg`)
			mustContain(t, content, `"$package_root/usr/share/icons/hicolor/scalable/apps/io.github.picocrypt_ng.Picocrypt-NG.svg"`)
			mustContain(t, content, `install -m 0644 dist/linux/io.github.picocrypt_ng.Picocrypt-NG.desktop`)
			mustContain(t, content, `sed -i 's|^Exec=.*|Exec=/usr/bin/picocrypt-ng-gui %f|'`)
			mustNotContain(t, content, `s|^Icon=`)
			mustNotContain(t, content, `s|^StartupWMClass=`)
			mustContain(t, content, `rsvg-convert --format png --width "$size" --height "$size" --output "$app_icon_png" images/key.svg`)
			mustContain(t, content, `dpkg-deb -c "${package_root}.deb" | grep -E 'usr/share/icons/hicolor/scalable/apps/io\.github\.picocrypt_ng\.Picocrypt-NG\.svg' >/dev/null`)
			for _, size := range []string{"16", "32", "48", "64", "128", "256"} {
				mustContain(t, content, `dpkg-deb -c "${package_root}.deb" | grep -E 'usr/share/icons/hicolor/`+size+`x`+size+`/apps/io\.github\.picocrypt_ng\.Picocrypt-NG\.png' >/dev/null`)
			}
		})
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

func TestAndroidPRWorkflowRunsCryptoRoundtripOnDevice(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/pr-test-build-android.yml")
	mustContain(t, content, "Run Unit Tests")
	mustContain(t, content, "./gradlew test")
	mustContain(t, content, ":app:compileDebugAndroidTestKotlin")
	mustContain(t, content, ":app:assembleDebugAndroidTest")
	// The PR gate now runs the real on-device Go encrypt/decrypt roundtrip so a crypto
	// regression on Android cannot merge green. Keep the emulator action SHA-pinned.
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustContain(t, content, "connectedDebugAndroidTest")
	mustContain(t, content, "-Pandroid.testInstrumentationRunnerArguments.class")
	mustContain(t, content, "OperationManagerIntegrationTest")

	// The emulator must run API 36 (matching targetSdk), not 34: API 35+ behavior --
	// the foreground-service dataSync timeout and Service.onTimeout(API 35+) -- is only
	// reachable there, so gating on API 34 is a false green for that path.
	prJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-android.yml"), "pr-test-build-android")
	prEmulator := mustHaveStepUsingPrefix(t, prJob, "ReactiveCircus/android-emulator-runner@")
	if got := prEmulator.With["api-level"]; got != 36 {
		t.Fatalf("PR emulator api-level = %v, want 36 (>= targetSdk for FGS/onTimeout coverage)", got)
	}
}

func TestAndroidPRWorkflowBuildsReleaseWithR8(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-android.yml")
	job := mustJob(t, workflow, "pr-test-build-android")

	releaseStep := mustStepNamed(t, job, "Build Release APK")
	mustContain(t, releaseStep.Run, "./gradlew :app:assembleRelease")

	appGradle := mustReadRepoFile(t, "android/app/build.gradle.kts")
	mustContain(t, appGradle, "isMinifyEnabled = true")
	mustContain(t, appGradle, "isShrinkResources = true")
}

func TestAndroidReleaseWorkflowKeepsSigningSecretsOutOfBuildJob(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	buildJob := mustJob(t, workflow, "build")
	releaseJob := mustJob(t, workflow, "release")

	mustStepNamed(t, buildJob, "Build Go Mobile AAR")
	mustStepNamed(t, buildJob, "Run Unit Tests")
	mustNotHaveStepNamed(t, buildJob, "Decode Android signing keystore")
	mustNotHaveStepNamed(t, buildJob, "Build Signed Release APK")

	decodeStep := mustStepNamed(t, releaseJob, "Decode Android signing keystore")
	if decodeStep.ID != "android-keystore" {
		t.Fatalf("release keystore decode step id = %q, want android-keystore", decodeStep.ID)
	}
	if _, ok := decodeStep.Env["ANDROID_KEYSTORE_BASE64"]; !ok {
		t.Fatal("release keystore decode step should declare ANDROID_KEYSTORE_BASE64")
	}
	for _, key := range []string{
		"ANDROID_KEYSTORE_PASSWORD",
		"ANDROID_KEY_ALIAS",
		"ANDROID_KEY_PASSWORD",
	} {
		if _, ok := decodeStep.Env[key]; ok {
			t.Fatalf("release keystore decode step must not declare env %q", key)
		}
		mustNotContain(t, decodeStep.Run, key)
	}
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEYSTORE_PASSWORD")
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEY_ALIAS")
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEY_PASSWORD")
	mustNotContain(t, decodeStep.Run, "$GITHUB_ENV")
	mustContain(t, decodeStep.Run, "path=$KEYSTORE_PATH")
	mustMatch(t, decodeStep.Run, `(?m)>>\s*"\$GITHUB_OUTPUT"`)

	buildSignedStep := mustStepNamed(t, releaseJob, "Build Signed Release APK")
	for _, key := range []string{
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PATH",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PASSWORD",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEY_ALIAS",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEY_PASSWORD",
	} {
		if _, ok := buildSignedStep.Env[key]; !ok {
			t.Fatalf("signed build step missing scoped env %q", key)
		}
	}
	if got := buildSignedStep.Env["ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PATH"]; got != "${{ steps.android-keystore.outputs.path }}" {
		t.Fatalf("signed build keystore path env = %q, want android-keystore step output", got)
	}
	downloadStep := mustHaveStepUsingPrefix(t, releaseJob, "actions/download-artifact@")
	mustMatch(t, downloadStep.Uses, `actions/download-artifact@[0-9a-f]{40}`)
}

func TestAndroidBuildWorkflowsUseJDK21(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-android.yml",
		".github/workflows/pr-test-build-android.yml",
		".github/workflows/android-instrumented.yml",
	} {
		workflow := mustReadWorkflowDoc(t, path)
		for jobName, job := range workflow.Jobs {
			setupSteps := 0
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-java@") {
					continue
				}
				setupSteps++
				if step.Name != "Set up JDK 21" {
					t.Fatalf("%s job %s setup-java step name = %q, want Set up JDK 21", path, jobName, step.Name)
				}
				if got := step.With["distribution"]; got != "temurin" {
					t.Fatalf("%s job %s setup-java distribution = %#v, want temurin", path, jobName, got)
				}
				if got := step.With["java-version"]; got != "21" {
					t.Fatalf("%s job %s setup-java java-version = %#v, want 21", path, jobName, got)
				}
			}
			if setupSteps == 0 {
				t.Fatalf("%s job %s has no actions/setup-java step", path, jobName)
			}
		}
	}

	mustContain(t, mustReadRepoFile(t, "mise.toml"), `java = "temurin-21"`)
	mustContain(t, mustReadRepoFile(t, "android/README.md"), "CI and recommended local builds use JDK 21")

	buildScript := mustReadRepoFile(t, "android/build-app")
	mustContain(t, buildScript, "JDK 21 is required")
	mustContain(t, buildScript, `"$JAVA_MAJOR" != "21"`)
	mustNotContain(t, buildScript, "JDK 17 is required")
}

func TestAndroidApiFloorStaysAt24(t *testing.T) {
	gradle := mustReadRepoFile(t, "android/app/build.gradle.kts")
	mustContain(t, gradle, "minSdk = 24")

	gomobile := mustReadRepoFile(t, "android/build-gomobile.sh")
	mustContain(t, gomobile, "-androidapi 24")
	mustContain(t, gomobile, "-ldflags=\"$GOMOBILE_LDFLAGS\"")

	readme := mustReadRepoFile(t, "android/README.md")
	mustContain(t, readme, "minimum API level 24")
}

func TestAndroidGradleSupplyChainVerificationConfigured(t *testing.T) {
	const gradle813Sha256 = "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"

	wrapper := mustReadRepoFile(t, "android/gradle/wrapper/gradle-wrapper.properties")
	mustContain(t, wrapper, "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-bin.zip")
	mustMatch(t, wrapper, `(?m)^distributionSha256Sum=`+gradle813Sha256+`$`)

	metadata := mustReadRepoFile(t, "android/gradle/verification-metadata.xml")
	mustContain(t, metadata, "<verification-metadata")
	mustContain(t, metadata, "<verify-metadata>true</verify-metadata>")
	mustMatch(t, metadata, `<sha256 value="[0-9a-f]{64}"`)

	var dependabot struct {
		Updates []struct {
			PackageEcosystem string `yaml:"package-ecosystem"`
			Directory        string `yaml:"directory"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/dependabot.yml")), &dependabot); err != nil {
		t.Fatalf("unmarshal dependabot yaml: %v", err)
	}
	for _, want := range []struct {
		ecosystem string
		directory string
	}{
		{ecosystem: "gomod", directory: "src/"},
		{ecosystem: "gradle", directory: "android/"},
		{ecosystem: "github-actions", directory: "/"},
	} {
		found := false
		for _, update := range dependabot.Updates {
			if update.PackageEcosystem == want.ecosystem && update.Directory == want.directory {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("dependabot updates missing package-ecosystem %q with directory %q together", want.ecosystem, want.directory)
		}
	}
}

func TestAndroidGomobileBuildUsesReproducibleLinkerFlags(t *testing.T) {
	content := mustReadRepoFile(t, "android/build-gomobile.sh")

	mustContain(t, content, `-ldflags="$GOMOBILE_LDFLAGS"`)
	mustContain(t, content, `-s -w -buildid=`)
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

	// Same API-36 requirement as the PR gate (FGS/onTimeout reachability).
	instrJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/android-instrumented.yml"), "android-instrumented")
	instrEmulator := mustHaveStepUsingPrefix(t, instrJob, "ReactiveCircus/android-emulator-runner@")
	if got := instrEmulator.With["api-level"]; got != 36 {
		t.Fatalf("instrumented emulator api-level = %v, want 36", got)
	}
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
		// actions/cache must be SHA-pinned for supply-chain safety, not floated on
		// a mutable major tag. Assert the 40-hex pin, not a specific version, so a
		// cache bump (e.g. the v4->v5 unification) does not churn this test.
		mustMatch(t, cacheStep.Uses, `actions/cache@[0-9a-f]{40}`)
		if cacheStep.With["path"] != `C:\go-legacy` {
			t.Fatalf("cache step path = %#v, want C:\\go-legacy", cacheStep.With["path"])
		}
	}
}
