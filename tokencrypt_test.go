package tokencrypt

import (
	"testing"
)

type testpair struct {
	decoded, encoded string
}


var tests = []testpair{
	{"a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8"},
	{"test", "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc"},
	{"08019215-B205-4416-B2FB-132962F9952F", "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"},
	{"перевірка", "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ"},
}


func TestBasic(t *testing.T) {

	tc, err := NewTokenCrypt([]byte("a"), []byte("b"), 1000)
	if err != nil {
		t.Error(err)
	}


	for _, test := range tests {
		val, err := tc.DecryptIf3ncr(test.encoded)
		if err != nil {
			t.Error(err)
		}
		if val != test.decoded {
			t.Fatalf("test failed %s", test.decoded)
		}
	}
}


func TestIdentity(t *testing.T) {

	tc, err := NewTokenCrypt([]byte("a"), []byte("b"), 1)
	if err != nil {
		t.Error(err)
	}


	for _, test := range tests {
		enc, err := tc.Encrypt3ncr(test.decoded)
		if err != nil {
			t.Error(err)
		}
		val, err := tc.DecryptIf3ncr(enc)
		if err != nil {
			t.Error(err)
		}
		if val != test.decoded {
			t.Fatalf("failed identity encrypt-decrypt %s", test.decoded)
		}
	}

}



