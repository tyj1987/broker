package dependencytest

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dependencies(t *testing.T, packages ...string) string {
	t.Helper()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	arguments := append([]string{"list", "-deps"}, packages...)
	command := exec.Command(goTool, arguments...)
	command.Dir = ".."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	return string(output)
}

func rejectDependency(t *testing.T, graph string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(graph, value) {
			t.Fatalf("forbidden dependency present: %s", value)
		}
	}
}

func TestImmutableProviderSDKDependencyIsolation(t *testing.T) {
	const (
		alibabaSDK        = "github.com/aliyun/alibabacloud-oss-go-sdk-v2/"
		alibabaKMSSDK     = "github.com/alibabacloud-go/kms-20160120/"
		alibabaCredential = "github.com/aliyun/credentials-go/"
		tencentSDK        = "github.com/tencentyun/cos-go-sdk-v5"
	)

	storeCommand := dependencies(t, "./cmd/audit-store")
	rejectDependency(t, storeCommand, alibabaSDK, tencentSDK)
	signerCommand := dependencies(t, "./cmd/audit-signer")
	rejectDependency(t, signerCommand, alibabaSDK, alibabaKMSSDK, alibabaCredential, tencentSDK)

	mirrorCommand := dependencies(t, "./cmd/audit-mirror-worker")
	if !strings.Contains(mirrorCommand, tencentSDK) {
		t.Fatal("Tencent mirror command does not contain its pinned SDK")
	}
	rejectDependency(t, mirrorCommand, alibabaSDK)

	credentialSource := dependencies(t, "./tencentcredential")
	rejectDependency(t, credentialSource, alibabaSDK, tencentSDK)

	primary := dependencies(t, "./auditoss")
	if !strings.Contains(primary, alibabaSDK) {
		t.Fatal("Alibaba adapter does not contain its pinned SDK")
	}
	rejectDependency(t, primary, tencentSDK)

	mirror := dependencies(t, "./auditcos")
	if !strings.Contains(mirror, tencentSDK) {
		t.Fatal("Tencent adapter does not contain its pinned SDK")
	}
	rejectDependency(t, mirror, alibabaSDK)
}
