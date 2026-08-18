// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong password entirely", hash)
	if err != nil {
		t.Fatalf("verify wrong password errored: %v", err)
	}
	if ok {
		t.Fatal("wrong password verified successfully")
	}
}

func TestPasswordHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same password")
	b, _ := HashPassword("same password")
	if a == b {
		t.Fatal("identical passwords produced identical hashes; salt is not applied")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{"", "notahash", "$argon2id$v=19$broken", "$bcrypt$v=19$m=1,t=1,p=1$a$b"} {
		if _, err := VerifyPassword("x", bad); !errors.Is(err, ErrInvalidHash) && err == nil {
			t.Fatalf("expected error for malformed hash %q", bad)
		}
	}
}

// The dummy hash used to equalise login timing must be a well-formed argon2id
// hash, otherwise the unknown-user path returns early and leaks timing.
func TestDummyHashIsWellFormed(t *testing.T) {
	if _, err := VerifyPassword("anything", dummyHash); err != nil {
		t.Fatalf("dummy hash is not usable for timing equalisation: %v", err)
	}
}

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role              Role
		valid, edit, admn bool
	}{
		{RoleAdmin, true, true, true},
		{RoleEditor, true, true, false},
		{RoleViewer, true, false, false},
		{Role("root"), false, false, false},
	}
	for _, c := range cases {
		if c.role.Valid() != c.valid {
			t.Errorf("%s: Valid()=%v want %v", c.role, c.role.Valid(), c.valid)
		}
		if c.role.CanEdit() != c.edit {
			t.Errorf("%s: CanEdit()=%v want %v", c.role, c.role.CanEdit(), c.edit)
		}
		if c.role.CanAdmin() != c.admn {
			t.Errorf("%s: CanAdmin()=%v want %v", c.role, c.role.CanAdmin(), c.admn)
		}
	}
}

func TestNewTokenIsUniqueAndHashed(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b {
		t.Fatal("NewToken returned the same value twice")
	}
	if len(HashToken(a)) != 32 {
		t.Fatalf("HashToken returned %d bytes, want 32", len(HashToken(a)))
	}
	if string(HashToken(a)) == a {
		t.Fatal("HashToken returned the raw token")
	}
}
