package workflowpolicy

import "testing"

func TestParseWorkflowYAMLExtractsPermissionsJobsAndSteps(t *testing.T) {
	content := `
permissions:
  contents: read
jobs:
  build:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
      - name: Release
        uses: softprops/action-gh-release@1234567890123456789012345678901234567890
        with:
          tag_name: v1.00
        env:
          GH_TOKEN: token
`

	workflow := mustParseWorkflowYAML(t, content)
	mustPermission(t, workflow.Permissions, "contents", "read")

	build := mustJob(t, workflow, "build")
	mustPermission(t, build.Permissions, "contents", "read")

	step := mustStepNamed(t, build, "Release")
	if step.Uses != "softprops/action-gh-release@1234567890123456789012345678901234567890" {
		t.Fatalf("step uses = %q", step.Uses)
	}
	if step.With["tag_name"] != "v1.00" {
		t.Fatalf("step with[tag_name] = %#v", step.With["tag_name"])
	}
	if step.Env["GH_TOKEN"] != "token" {
		t.Fatalf("step env[GH_TOKEN] = %q", step.Env["GH_TOKEN"])
	}
}

func TestMustParseWorkflowYAMLFindsStepByUses(t *testing.T) {
	content := `
jobs:
  release:
    steps:
      - uses: actions/download-artifact@v8
      - uses: softprops/action-gh-release@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`

	workflow := mustParseWorkflowYAML(t, content)
	release := mustJob(t, workflow, "release")
	step := mustStepUsing(t, release, "softprops/action-gh-release@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if step.Uses == "" {
		t.Fatal("expected matching step uses")
	}
}
