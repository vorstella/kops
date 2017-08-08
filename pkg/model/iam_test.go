/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package model

import (
	"testing"
)

func Test_RoleRegex(t *testing.T) {
	grid := []struct {
		ARN      string
		Expected string
		Pass     bool
	}{
		{
			"arn:aws:iam::034201736311:instance-profile/prn/aws/syd/non/bffoo/sdskube/poc1/20/admin/bfsoo-sdskube-poc1-20-syd-kops-InstanceRole-I2DULW7329QA",
			"bfsoo-sdskube-poc1-20-syd-kops-InstanceRole-I2DULW7329QA",
			true,
		},
		{
			"arn:aws:iam::034201736311:role/prn/aws/syd/non/bffoo/sdskube/poc1/20/admin/bar/bfsoo-sdskube-poc1-20-syd-kops-InstanceRole-I2DULW7329QA",
			"bfsoo-sdskube-poc1-20-syd-kops-InstanceRole-I2DULW7329QA",
			false,
		},
		{
			"arn:aws:iam::962942490108:instance-profile/kops-custom-master-role",
			"kops-custom-master-role",
			true,
		},
	}
	for _, g := range grid {
		rs, err := findCustomAuthNameFromArn(&g.ARN)
		if err != nil && g.Pass {
			t.Errorf("expected to match and did not")
		}

		if rs != g.Expected {
			t.Errorf("matched incorrect value, expected: %q, got %q", g.Expected, rs)
		}

	}
}
