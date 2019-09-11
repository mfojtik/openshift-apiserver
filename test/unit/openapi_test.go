package unit

import (
	"strings"
	"testing"

	"github.com/openshift/openshift-apiserver/test/unit/fixtures"
	"k8s.io/client-go/kubernetes"
)

func TestOpenshiftOpenAPIServed(t *testing.T) {
	s, err := fixtures.StartTestServerWithInProcessEtcd(t)
	if err != nil {
		t.Fatal(err)
	}

	client, err := kubernetes.NewForConfig(s.ClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	result := client.CoreV1().RESTClient().Get().AbsPath("/openapi/v2").Do()
	if err := result.Error(); err != nil {
		t.Fatal(err)
	}

	openAPIBytes, err := result.Raw()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(openAPIBytes), `"group":"build.openshift.io","kind":"Build"`) {
		t.Errorf("/openapi/v2 does not contain Openshift OpenAPI data")
	}

	defer s.TearDownFn()
}
