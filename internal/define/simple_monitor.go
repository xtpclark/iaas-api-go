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

package define

import (
	"github.com/sacloud/iaas-api-go/internal/define/names"
	"github.com/sacloud/iaas-api-go/internal/define/ops"
	"github.com/sacloud/iaas-api-go/internal/dsl"
	"github.com/sacloud/iaas-api-go/internal/dsl/meta"
	"github.com/sacloud/iaas-api-go/naked"
	"github.com/sacloud/iaas-api-go/types"
)

const (
	simpleMonitorAPIName     = "SimpleMonitor"
	simpleMonitorAPIPathName = "commonserviceitem"
)

var simpleMonitorAPI = &dsl.Resource{
	Name:       simpleMonitorAPIName,
	PathName:   simpleMonitorAPIPathName,
	PathSuffix: dsl.CloudAPISuffix,
	IsGlobal:   true,
	Operations: dsl.Operations{
		// find
		ops.FindCommonServiceItem(simpleMonitorAPIName, simpleMonitorNakedType, findParameter, simpleMonitorView),

		// create
		ops.CreateCommonServiceItem(simpleMonitorAPIName, simpleMonitorNakedType, simpleMonitorCreateParam, simpleMonitorView),

		// read
		ops.ReadCommonServiceItem(simpleMonitorAPIName, simpleMonitorNakedType, simpleMonitorView),

		// update
		ops.UpdateCommonServiceItem(simpleMonitorAPIName, simpleMonitorNakedType, simpleMonitorUpdateParam, simpleMonitorView),
		// updateSettings
		ops.UpdateCommonServiceItemSettings(simpleMonitorAPIName, simpleMonitorUpdateSettingsNakedType, simpleMonitorUpdateSettingsParam, simpleMonitorView),

		// delete
		ops.Delete(simpleMonitorAPIName),

		// momitor
		ops.MonitorChild(simpleMonitorAPIName, "ResponseTime", "/activity/responsetimesec",
			monitorParameter, monitors.responseTimeSecModel()),

		// health check
		ops.HealthStatus(simpleMonitorAPIName, simpleMonitorHealthStatusNakedType, simpleMonitorHealthStatus),
	},
}

var (
	simpleMonitorNakedType               = meta.Static(naked.SimpleMonitor{})
	simpleMonitorUpdateSettingsNakedType = meta.Static(naked.SimpleMonitorSettingsUpdate{})
	simpleMonitorHealthStatusNakedType   = meta.Static(naked.SimpleMonitorHealthCheckStatus{})

	simpleMonitorView = &dsl.Model{
		Name:      simpleMonitorAPIName,
		NakedType: simpleMonitorNakedType,
		Fields: []*dsl.FieldDesc{
			fields.ID(),
			fields.Name(),
			fields.Description(),
			fields.Tags(),
			fields.Availability(),
			fields.IconID(),
			fields.CreatedAt(),
			fields.ModifiedAt(),
			fields.Class(),

			// status
			fields.SimpleMonitorTarget(),

			// settings
			fields.SimpleMonitorDelayLoop(),
			fields.SimpleMonitorMaxCheckAttempts(),
			fields.SimpleMonitorRetryInterval(),
			fields.SimpleMonitorEnabled(),
			// settings - health check
			fields.SimpleMonitorHealthCheck(),
			// settings - email
			fields.SimpleMonitorNotifyEmailEnabled(),
			fields.SimpleMonitorNotifyEmailHTML(),
			// settings - slack
			fields.SimpleMonitorNotifySlackEnabled(),
			fields.SimpleMonitorSlackWebhooksURL(),
			// settings - notify interval
			fields.SimpleMonitorNotifyInterval(),
			// settings - timeout
			fields.SimpleMonitorTimeout(),
			// settings hash
			fields.SettingsHash(),
		},
	}

	simpleMonitorCreateParam = &dsl.Model{
		Name:      names.CreateParameterName(simpleMonitorAPIName),
		NakedType: simpleMonitorNakedType,
		ConstFields: []*dsl.ConstFieldDesc{
			{
				Name: "Class",
				Type: meta.TypeString,
				Tags: &dsl.FieldTags{
					MapConv: "Provider.Class",
				},
				Value: `"simplemon"`,
			},
		},
		Fields: []*dsl.FieldDesc{
			// creation time only
			{
				Name: "Target",
				Type: meta.TypeString,
				Tags: &dsl.FieldTags{
					MapConv: "Name/Status.Target", // NameとStatus.Targetに同じ値を設定
				},
			},

			// settings
			fields.SimpleMonitorMaxCheckAttempts(),
			fields.SimpleMonitorRetryInterval(),
			fields.SimpleMonitorDelayLoop(),
			fields.SimpleMonitorEnabled(),
			// settings - health check
			fields.SimpleMonitorHealthCheck(),

			// settings - email
			fields.SimpleMonitorNotifyEmailEnabled(),
			fields.SimpleMonitorNotifyEmailHTML(),

			// settings - slack
			fields.SimpleMonitorNotifySlackEnabled(),
			fields.SimpleMonitorSlackWebhooksURL(),
			fields.SimpleMonitorNotifyInterval(),

			fields.SimpleMonitorTimeout(),

			fields.Description(),
			fields.Tags(),
			fields.IconID(),
		},
	}

	simpleMonitorUpdateSettingsParam = &dsl.Model{
		Name:      names.UpdateSettingsParameterName(simpleMonitorAPIName),
		NakedType: simpleMonitorNakedType,
		Fields: []*dsl.FieldDesc{
			// settings
			fields.SimpleMonitorMaxCheckAttempts(),
			fields.SimpleMonitorRetryInterval(),
			fields.SimpleMonitorDelayLoop(),
			fields.SimpleMonitorEnabled(),
			// settings - health check
			fields.SimpleMonitorHealthCheck(),
			// settings - email
			fields.SimpleMonitorNotifyEmailEnabled(),
			fields.SimpleMonitorNotifyEmailHTML(),
			// settings - slack
			fields.SimpleMonitorNotifySlackEnabled(),
			fields.SimpleMonitorSlackWebhooksURL(),

			fields.SimpleMonitorNotifyInterval(),

			fields.SimpleMonitorTimeout(),
			// settings hash
			fields.SettingsHash(),
		},
	}

	simpleMonitorUpdateParam = &dsl.Model{
		Name:      names.UpdateParameterName(simpleMonitorAPIName),
		NakedType: simpleMonitorNakedType,
		Fields: []*dsl.FieldDesc{
			fields.Description(),
			fields.Tags(),
			fields.IconID(),

			// settings
			fields.SimpleMonitorMaxCheckAttempts(),
			fields.SimpleMonitorRetryInterval(),
			fields.SimpleMonitorDelayLoop(),
			fields.SimpleMonitorEnabled(),
			// settings - health check
			fields.SimpleMonitorHealthCheck(),
			// settings - email
			fields.SimpleMonitorNotifyEmailEnabled(),
			fields.SimpleMonitorNotifyEmailHTML(),
			// settings - slack
			fields.SimpleMonitorNotifySlackEnabled(),
			fields.SimpleMonitorSlackWebhooksURL(),

			fields.SimpleMonitorNotifyInterval(),

			fields.SimpleMonitorTimeout(),
			// settings hash
			fields.SettingsHash(),
		},
	}

	simpleMonitorHealthStatus = &dsl.Model{
		Name:      "SimpleMonitorHealthStatus",
		NakedType: simpleMonitorHealthStatusNakedType,
		Fields: []*dsl.FieldDesc{
			fields.Def("LastCheckedAt", meta.TypeTime),
			fields.Def("LastHealthChangedAt", meta.TypeTime),
			fields.Def("Health", meta.Static(types.ESimpleMonitorHealth(""))),
			fields.Def("LatestLogs", meta.TypeStringSlice),
		},
	}
)
