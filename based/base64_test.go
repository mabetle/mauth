package based_test

import (
	"github.com/mabetle/mauth/based"
	"testing"
)

var encoder = based.NewDefault()

func TestDecode(t *testing.T) {
	str := "hello"
	encStr := encoder.EncodeString(str)
	t.Logf("%s Encode to : %s\n", str, encStr)
	decStr, _ := encoder.DecodeString(encStr)
	t.Logf("%s Decode to : %s\n", encStr, decStr)

	if str != decStr {
		t.Errorf("decode not eqault to original word. Old:%s Decode:%s", str, decStr)
	}
	t.Log("Success encode and decode.\n")
	//t.Fail()
}
