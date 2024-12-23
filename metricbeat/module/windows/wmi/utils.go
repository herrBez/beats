// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package wmi

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	base "github.com/microsoft/wmi/go/wmi"
	wmi "github.com/microsoft/wmi/pkg/wmiinstance"
)

// Define an interface to allow unit-testing the timing out issues
type WmiQueryInterface interface {
	QueryInstances(query string) ([]*wmi.WmiInstance, error)
}

// Define a type for performing conversion
type WMI_EXTRA_CONVERSION func(string) (interface{}, error)

func ConvertUint64(v string) (interface{}, error) {
	return strconv.ParseUint(v, 10, 64)
}

func ConvertSint64(v string) (interface{}, error) {
	return strconv.ParseInt(v, 10, 64)
}

func ConvertDatetime(v string) (interface{}, error) {
	layout := "20060102150405.999999-0700"
	return time.Parse(layout, v+"0")
}

func ConvertString(v string) (interface{}, error) {
	return v, nil
}

// Given a Property it returns its CIM Type Qualifier
// https://learn.microsoft.com/en-us/windows/win32/wmisdk/cimtype-qualifier
// We assume that it is **always** defined for every property to simiplifying
// the error handling
func getPropertyType(property *ole.IDispatch) base.WmiType {
	rawType := oleutil.MustGetProperty(property, "CIMType")

	value, err := wmi.GetVariantValue(rawType)
	if err != nil {
		panic("Error retrieving the wmi property type")
	}

	return base.WmiType(value.(int32))
}

// Function that returns a "raw" Property that has also a Type
func getProperty(instance *wmi.WmiInstance, propertyName string) (*ole.IDispatch, error) {
	// Documentation: https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemobject-properties-
	rawResult, err := oleutil.GetProperty(instance.GetIDispatch(), "Properties_")
	if err != nil {
		return nil, err
	}

	// SWbemObjectEx.Properties_ returns
	// an SWbemPropertySet object that contains the collection
	// of sytem properties for the c class
	sWbemObjectExAsIDispatch := rawResult.ToIDispatch()
	defer rawResult.Clear()

	// Get the property
	sWbemProperty, err := oleutil.CallMethod(sWbemObjectExAsIDispatch, "Item", propertyName)
	if err != nil {
		return nil, err
	}

	return sWbemProperty.ToIDispatch(), nil
}

// Given an instance and a property Name, it returns the conversion function
func GetConvertFunction(instance *wmi.WmiInstance, propertyName string) (WMI_EXTRA_CONVERSION, error) {
	rawProperty, err := getProperty(instance, propertyName)
	if err != nil {
		return nil, err
	}

	propType := getPropertyType(rawProperty)

	var f WMI_EXTRA_CONVERSION

	switch propType {
	case base.WbemCimtypeDatetime:
		f = ConvertDatetime
	case base.WbemCimtypeUint64:
		f = ConvertUint64
	case base.WbemCimtypeSint64:
		f = ConvertSint64
	default: // For all other type we return the identity function
		f = ConvertString
	}
	return f, err
}

// Wrapper of the session.QueryInstances function that execute a query for at most a timeout
// Note that the underlying query will continue run
func ExecuteGuardedQueryInstances(session WmiQueryInterface, query string, timeout time.Duration) ([]*wmi.WmiInstance, error) {
	var rows []*wmi.WmiInstance
	var err error
	done := make(chan error)
	timedout := false

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		rows, err = session.QueryInstances(query)
		if !timedout {
			done <- err
		} else {
			// We eventually fetched the documents, let us free them
			if err != nil {
				wmi.CloseAllInstances(rows)
			} else {
				logp.L().Errorf("Help, error %v", err)
			}
		}

	}()

	select {
	case <-ctx.Done():
		err = fmt.Errorf("query '%s' exceeded the timeout of %s", query, timeout)
		timedout = true
		close(done)
	case <-done:
		// Query completed in time either successfully or with an error
	}

	return rows, err
}
