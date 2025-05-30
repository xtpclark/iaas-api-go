// Copyright 2022-2025 The sacloud/iaas-api-go Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iaas

import (
	"errors"
	"testing"
)

func TestNoResultsError(t *testing.T) {
	cases := []struct {
		in     error
		expect bool
	}{
		{
			in:     nil,
			expect: false,
		},
		{
			in:     errors.New("foo"),
			expect: false,
		},
		{
			in:     NewNoResultsError(),
			expect: true,
		},
	}

	for _, tc := range cases {
		got := IsNoResultsError(tc.in)
		if got != tc.expect {
			t.Errorf("got unexpected value: expected: %t got: %t", tc.expect, got)
		}
	}
}
