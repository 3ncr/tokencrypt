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

func TestArgon2idIdentity(t *testing.T) {

	tc, err := NewArgon2idTokenCrypt([]byte("correct horse battery staple"), []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
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

func TestArgon2idWrongSecretFails(t *testing.T) {

	salt := []byte("0123456789abcdef")

	tc, err := NewArgon2idTokenCrypt([]byte("right secret"), salt)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := tc.Encrypt3ncr("hello")
	if err != nil {
		t.Fatal(err)
	}

	other, err := NewArgon2idTokenCrypt([]byte("wrong secret"), salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.DecryptIf3ncr(enc); err == nil {
		t.Fatal("expected decryption with wrong secret to fail")
	}
}

func TestArgon2idShortSalt(t *testing.T) {

	if _, err := NewArgon2idTokenCrypt([]byte("secret"), []byte("short")); err == nil {
		t.Fatal("expected error for salt shorter than 16 bytes")
	}
}
