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

package fake

import (
	"context"

	"github.com/sacloud/iaas-api-go"
	"github.com/sacloud/iaas-api-go/types"
	"golang.org/x/crypto/ssh"
)

//nolint:gosec
var (
	// GeneratedPublicKey ダミー公開鍵
	GeneratedPublicKey = ``
	// GeneratedPrivateKey ダミー秘密鍵
	GeneratedPrivateKey = ``
	// GeneratedFingerprint ダミーフィンガープリント
	GeneratedFingerprint = ""
)

// Find is fake implementation
func (o *SSHKeyOp) Find(ctx context.Context, conditions *iaas.FindCondition) (*iaas.SSHKeyFindResult, error) {
	results, _ := find(o.key, iaas.APIDefaultZone, conditions)
	var values []*iaas.SSHKey
	for _, res := range results {
		dest := &iaas.SSHKey{}
		copySameNameField(res, dest)
		values = append(values, dest)
	}
	return &iaas.SSHKeyFindResult{
		Total:   len(results),
		Count:   len(results),
		From:    0,
		SSHKeys: values,
	}, nil
}

// Create is fake implementation
func (o *SSHKeyOp) Create(ctx context.Context, param *iaas.SSHKeyCreateRequest) (*iaas.SSHKey, error) {
	result := &iaas.SSHKey{}
	copySameNameField(param, result)
	fill(result, fillID, fillCreatedAt)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.PublicKey))
	if err != nil {
		return nil, err
	}
	result.Fingerprint = ssh.FingerprintLegacyMD5(pk)

	putSSHKey(iaas.APIDefaultZone, result)
	return result, nil
}

// Generate is fake implementation
func (o *SSHKeyOp) Generate(ctx context.Context, param *iaas.SSHKeyGenerateRequest) (*iaas.SSHKeyGenerated, error) {
	key := &iaas.SSHKey{}
	copySameNameField(param, key)
	fill(key, fillID, fillCreatedAt)

	result := &iaas.SSHKeyGenerated{}
	copySameNameField(key, result)

	result.PublicKey = GeneratedPublicKey
	result.PrivateKey = GeneratedPrivateKey
	result.Fingerprint = GeneratedFingerprint

	putSSHKey(iaas.APIDefaultZone, key)
	return result, nil
}

// Read is fake implementation
func (o *SSHKeyOp) Read(ctx context.Context, id types.ID) (*iaas.SSHKey, error) {
	value := getSSHKeyByID(iaas.APIDefaultZone, id)
	if value == nil {
		return nil, newErrorNotFound(o.key, id)
	}
	dest := &iaas.SSHKey{}
	copySameNameField(value, dest)
	return dest, nil
}

// Update is fake implementation
func (o *SSHKeyOp) Update(ctx context.Context, id types.ID, param *iaas.SSHKeyUpdateRequest) (*iaas.SSHKey, error) {
	value, err := o.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	copySameNameField(param, value)

	putSSHKey(iaas.APIDefaultZone, value)
	return value, nil
}

// Delete is fake implementation
func (o *SSHKeyOp) Delete(ctx context.Context, id types.ID) error {
	_, err := o.Read(ctx, id)
	if err != nil {
		return err
	}

	ds().Delete(o.key, iaas.APIDefaultZone, id)
	return nil
}
