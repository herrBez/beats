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

//go:build windows

package wmi

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	base "github.com/microsoft/wmi/go/wmi"
	wmi "github.com/microsoft/wmi/pkg/wmiinstance"

	"github.com/elastic/elastic-agent-libs/logp"
)

// Utilities related to Type conversion

type WmiConversionFunction func(interface{}) (interface{}, error)

func ConvertUint64(v interface{}) (interface{}, error) {
	switch v.(type) {
	case string:
		return strconv.ParseUint(v.(string), 10, 64)
	default:
		return nil, fmt.Errorf("Expect string")
	}
}

func ConvertSint64(v interface{}) (interface{}, error) {
	switch v.(type) {
	case string:
		return strconv.ParseInt(v.(string), 10, 64)
	default:
		return nil, fmt.Errorf("Expect string")
	}
}

const WMI_DATETIME_LAYOUT string = "20060102150405.999999"
const TIMEZONE_LAYOUT string = "-07:00"

// The CIMDateFormat is defined as "yyyymmddHHMMSS.mmmmmmsUUU".
// Example: "20231224093045.123456+000"
// More information: https://learn.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime
//
// The "yyyyMMddHHmmSS.mmmmmm" part can be parsed using time.Parse, but Go's time package does not support parsing the "sUUU"
// part (the sign and minute offset from UTC).
//
// Here, "s" represents the sign (+ or -), and "UUU" represents the UTC offset in minutes.
//
// The approach for handling this is:
// 1. Extract the sign ('+' or '-') from the string.
// 2. Normalize the offset from minutes to the standard `hh:mm` format.
// 3. Concatenate the "yyyyMMddHHmmSS.mmmmmm" part with the normalized offset.
// 4. Parse the combined string using time.Parse to return a time.Date object.
func ConvertDatetime(vi interface{}) (interface{}, error) {
	switch vi.(type) {
	case string:
		break
	default:
		return nil, fmt.Errorf("Expect string")
	}

	v := vi.(string)

	if len(v) != 25 {
		return nil, fmt.Errorf("datetime is invalid: the datetime is expected to be exactly 25 characters long, got: %s", v)
	}

	// Extract the sign (either '+' or '-')
	utcOffsetSign := v[21]
	if utcOffsetSign != '+' && utcOffsetSign != '-' {
		return nil, fmt.Errorf("datetime is invalid: the offset sign is expected to be either + or -")
	}

	// Extract UTC offset (last 3 characters)
	utcOffsetStr := v[22:]
	utcOffset, err := strconv.ParseInt(utcOffsetStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("datetime is invalid: error parsing UTC offset: %w", err)
	}
	offsetHours := utcOffset / 60
	offsetMinutes := utcOffset % 60

	// Build the complete date string including the UTC offset in the format yyyyMMddHHmmss.mmmmmm+hh:mm
	// Concatenate the date string with the offset formatted as "+hh:mm"
	dateString := fmt.Sprintf("%s%c%02d:%02d", v[:21], utcOffsetSign, offsetHours, offsetMinutes)

	// Parse the combined datetime string using the defined layout
	date, err := time.Parse(WMI_DATETIME_LAYOUT+TIMEZONE_LAYOUT, dateString)
	if err != nil {
		return nil, fmt.Errorf("datetime is invalid: error parsing the final datetime: %w", err)
	}

	return date, err
}

func ConvertIdentity(v interface{}) (interface{}, error) {
	return v, nil
}

// Given a Property it returns its CIM Type Qualifier
// https://learn.microsoft.com/en-us/windows/win32/wmisdk/cimtype-qualifier
func getPropertyType(property *ole.IDispatch) (base.WmiType, error) {
	rawType := oleutil.MustGetProperty(property, "CIMType")

	value, err := wmi.GetVariantValue(rawType)
	if err != nil {
		return base.WmiType(0), err
	}

	return base.WmiType(value.(int32)), nil
}

// Returns the "raw" SWbemProperty containing type information for a given property.
//
// The microsoft/wmi library does not have a function that given an instance and a property name
// returns the wmi.wmiProperty object. This function mimics the behavior of the `GetSystemProperty`
// method in the wmi.wmiInstance struct and applies it on the Properties_ property
// https://github.com/microsoft/wmi/blob/v0.25.2/pkg/wmiinstance/WmiInstance.go#L87
//
// Note: We are not instantiating a wmi.wmiProperty because of this issue
// https://github.com/microsoft/wmi/issues/150
// Once this issue is resolved, we can instantiate a wmi.WmiProperty and eliminate
// the need for the "getPropertyType" function.
func getProperty(instance *wmi.WmiInstance, propertyName string, logger *logp.Logger) (*ole.IDispatch, error) {
	// Documentation: https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemobject-properties-
	rawResult, err := oleutil.GetProperty(instance.GetIDispatch(), "Properties_")
	if err != nil {
		return nil, err
	}

	// SWbemObjectEx.Properties_ returns
	// an SWbemPropertySet object that contains the collection
	// of properties for the c class
	sWbemObjectExAsIDispatch := rawResult.ToIDispatch()
	defer func() {
		if cerr := rawResult.Clear(); cerr != nil {
			logger.Debugf("failed to release connection: %w", err)
		}
	}()

	// Get the property
	sWbemProperty, err := oleutil.CallMethod(sWbemObjectExAsIDispatch, "Item", propertyName)
	if err != nil {
		return nil, err
	}

	return sWbemProperty.ToIDispatch(), nil
}

// Given an instance and a property Name, it returns the appropriate conversion function
func GetConvertFunction(instance *wmi.WmiInstance, propertyName string, logger *logp.Logger) (WmiConversionFunction, error) {
	rawProperty, err := getProperty(instance, propertyName, logger)
	if err != nil {
		return nil, err
	}
	propType, err := getPropertyType(rawProperty)
	if err != nil {
		return nil, fmt.Errorf("could not fetch CIMType for property '%s' with error %w", propertyName, err)
	}

	var f WmiConversionFunction

	switch propType {
	case base.WbemCimtypeDatetime:
		f = ConvertDatetime
	case base.WbemCimtypeUint64:
		f = ConvertUint64
	case base.WbemCimtypeSint64:
		f = ConvertSint64
	default: // For all other types we return the identity function
		f = ConvertIdentity
	}
	return f, err
}

// Builds a set (map) of property names for quick lookup
func buildPropertySet(properties []string) map[string]bool {
	propertySet := make(map[string]bool, len(properties))
	for _, prop := range properties {
		propertySet[prop] = true
	}
	return propertySet
}

func errorOnClassDoesNotExist(rows []*wmi.WmiInstance, queryConfig QueryConfig) error {
	switch len(rows) {
	case 0:
		return fmt.Errorf("Class '%s' not found in namespace '%s'", queryConfig.Class, queryConfig.Namespace)
	case 1:
		return nil
	default:
		return fmt.Errorf("Unexpected case: Metaclass should return only a single entry for the class %s", queryConfig.Class)
	}
}

// Filters valid properties from an instance
// Valid properties are the ones contained in the instance taken from the meta_class
func filterValidProperties(instance *wmi.WmiInstance, properties []string) ([]string, []string) {
	if len(properties) == 0 {
		return instance.GetClass().GetPropertiesNames(), []string{}
	}

	validProperties := []string{}
	invalidProperties := []string{}
	for _, p := range properties {
		if _, err := instance.GetProperty(p); err == nil {
			validProperties = append(validProperties, p)
		} else {
			invalidProperties = append(invalidProperties, p)
		}
	}
	return validProperties, invalidProperties
}

func addSchemaToQueryConfig(session WmiQueryInterface, queryConfig *QueryConfig, logger *logp.Logger) error {
	// Fetch the meta class
	query := fmt.Sprintf("SELECT * FROM meta_class WHERE __Class = '%s'", queryConfig.Class)
	rows, err := session.QueryInstances(query)
	if err != nil {
		return fmt.Errorf("Could not execute meta_class query: %v", err)
	}

	defer wmi.CloseAllInstances(rows)

	// Double check if the class does exist
	err = errorOnClassDoesNotExist(rows, *queryConfig)
	if err != nil {
		return err
	}

	instance := rows[0]

	// Valid Properties contains the properties that are both contained in the
	// user-provided lists and in the properties of the class
	validProperties, invalidProperties := filterValidProperties(instance, queryConfig.Properties)

	if len(invalidProperties) > 0 {
		logger.Warnf("We are going to ignore the properties '%s' because '%s' class in namespace '%s' does not contain those properties. Please amend your configuration or check why it's the case", invalidProperties, queryConfig.Class, queryConfig.Namespace)
	}
	if len(validProperties) == 0 {
		return fmt.Errorf("All the properties listed  are invalid %v. We are skipping the query", invalidProperties)
	}

	// Extract schema
	schema := make(map[string]WmiConversionFunction)
	for _, property := range validProperties {
		convertFunction, err := GetConvertFunction(instance, property, logger)
		if err != nil {
			return fmt.Errorf("Could not fetch convert function for property %s: %v", property, err)
		}
		schema[property] = convertFunction
	}

	// For the empty array we keep '*'
	if len(queryConfig.Properties) != 0 {
		queryConfig.Properties = validProperties
	}

	queryConfig.Schema = schema
	queryConfig.compileQuery()

	return nil
}

// Utilities related to Warning Threshold

// Define an interface to allow unit-testing long-running queries
// *wmi.wmiSession is an implementation of this interface
type WmiQueryInterface interface {
	QueryInstances(query string) ([]*wmi.WmiInstance, error)
}

// Wrapper of the session.QueryInstances function that execute a query for at most a timeout
// after which we stop actively waiting.
// Note that the underlying query will continue to run, until the query completes or the WMI Arbitrator stops the query
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/new-wmi-arbitrator-behavior-in-windows-server
func ExecuteGuardedQueryInstances(session WmiQueryInterface, query string, timeout time.Duration, logger *logp.Logger) ([]*wmi.WmiInstance, error) {
	var rows []*wmi.WmiInstance
	var err error
	done := make(chan error)
	timedout := false

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		start_time := time.Now()
		rows, err = session.QueryInstances(query)
		if !timedout {
			done <- err
		} else {
			timeSince := time.Since(start_time)
			baseMessage := fmt.Sprintf("The query '%s' that exceeded the warning threshold terminated after %s", query, timeSince)
			var tailMessage string
			// We eventually fetched the documents, let us free them
			if err == nil {
				tailMessage = "successfully. The result will be ignored"
				wmi.CloseAllInstances(rows)
			} else {
				tailMessage = fmt.Sprintf("with an error %v", err)
			}
			logger.Warn("%s %s", baseMessage, tailMessage)
		}
	}()

	select {
	case <-ctx.Done():
		err = fmt.Errorf("the execution of the query '%s' exceeded the warning threshold of %s", query, timeout)
		timedout = true
		close(done)
	case <-done:
		// Query completed in time either successfully or with an error
	}
	return rows, err
}
