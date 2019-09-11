package unit

import (
	"testing"

	"github.com/openshift/openshift-apiserver/test/unit/fixtures"
)

func TestServerUp(t *testing.T) {
	s, err := fixtures.StartTestServerWithInProcessEtcd(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.TearDownFn()
}
