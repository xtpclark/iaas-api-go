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

package naked

import (
	"time"

	"github.com/sacloud/iaas-api-go/types"
)

// Subnet サブネット
type Subnet struct {
	ID             types.ID    `json:",omitempty" yaml:"id,omitempty" structs:",omitempty"`
	ServiceClass   string      `json:",omitempty" yaml:"service_class,omitempty" structs:",omitempty"`
	CreatedAt      *time.Time  `json:",omitempty" yaml:"created_at,omitempty" structs:",omitempty"`
	DefaultRoute   string      `json:",omitempty" yaml:"default_route,omitempty" structs:",omitempty"`
	NetworkAddress string      `json:",omitempty" yaml:"network_address,omitempty" structs:",omitempty"`
	NetworkMaskLen int         `json:",omitempty" yaml:"network_mask_len,omitempty" structs:",omitempty"`
	ServiceID      types.ID    `json:",omitempty" yaml:"service_id,omitempty" structs:",omitempty"`
	StaticRoute    string      `json:",omitempty" yaml:"static_route,omitempty" structs:",omitempty"`
	NextHop        string      `json:",omitempty" yaml:"next_hop,omitempty" structs:",omitempty"`
	Switch         *Switch     `json:",omitempty" yaml:"switch,omitempty" structs:",omitempty"`
	Internet       *Internet   `json:",omitempty" yaml:"internet,omitempty" structs:",omitempty"`
	IPAddresses    interface{} `json:",omitempty" yaml:"ip_addresses,omitempty" structs:",omitempty"`
}

// SubnetIPAddressRange ルータ+スイッチのスイッチ配下から参照できるSubnetでの割り当てられているIPアドレス範囲
type SubnetIPAddressRange struct {
	Min string `yaml:"min"`
	Max string `yaml:"max"`
}
