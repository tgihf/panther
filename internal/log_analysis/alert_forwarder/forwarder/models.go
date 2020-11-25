package forwarder

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
)

const (
	// The type of an Alert that is triggered because of a rule encountering an error
	RuleErrorType = "RULE_ERROR"

	alertTablePartitionKey        = "id"
	alertTableLogTypesAttribute   = "logTypes"
	alertTableEventCountAttribute = "eventCount"
	alertTableUpdateTimeAttribute = "updateTime"
)

// TODO: Update Generated custom fields dynamodbav tags
// AlertDedupEvent represents the event stored in the alert dedup DDB table by the rules engine
type AlertDedupEvent struct {
	RuleID                       string    `dynamodbav:"ruleId"`
	RuleVersion                  string    `dynamodbav:"ruleVersion"`
	DeduplicationString          string    `dynamodbav:"dedup"`
	CreationTime                 time.Time `dynamodbav:"creationTime"`
	UpdateTime                   time.Time `dynamodbav:"updateTime"`
	EventCount                   int64     `dynamodbav:"eventCount"`
	LogTypes                     []string  `dynamodbav:"logTypes,stringset"`
	AlertContext                 *string   `dynamodbav:"context,string"`
	Type                         string    `dynamodbav:"type"`
	GeneratedTitle               *string   `dynamodbav:"title,string"`       // The title that was generated dynamically using Python. Might be null.
	GeneratedDescription         *string   `dynamodbav:"description,string"` // The description that was generated dynamically using Python. Might be null.
	GeneratedReference           *string   `dynamodbav:"-"`                  // The reference that was generated dynamically using Python. Might be null.
	GeneratedSeverity            *string    `dynamodbav:"-"`                  // The severity that was generated dynamically using Python. Might be null.
	GeneratedRunbook             *string   `dynamodbav:"-"`                  // The runbook that was generated dynamically using Python. Might be null.
	GeneratedDestinationOverride []string  `dynamodbav:"-"`                  // The destination override that was generated dynamically using Python. Might be null.
	AlertCount                   int64     `dynamodbav:"-"`                  // There is no need to store this item in DDB
}

// Alert contains all the fields associated to the alert stored in DDB
type Alert struct {
	ID                  string    `dynamodbav:"id,string"`
	TimePartition       string    `dynamodbav:"timePartition,string"`
	Severity            *string    `dynamodbav:"severity,string"`
	RuleDisplayName     *string   `dynamodbav:"ruleDisplayName,string"`
	FirstEventMatchTime time.Time `dynamodbav:"firstEventMatchTime,string"`
	LogTypes            []string  `dynamodbav:"logTypes,stringset"`
	Title               *string    `dynamodbav:"title,string"`                  // The alert title. It will be the Python-generated title or a default one if no Python-generated title is available.
	Description         *string   `dynamodbav:"description,string"`            // The alert description. It will be the Python-generated description or a default one if no Python-generated description is available.
	Reference           *string   `dynamodbav:"reference,string"`              // The alert reference. It will be the Python-generated description or a default one if no Python-generated reference is available.
	Runbook             *string   `dynamodbav:"runbook,string"`                // The alert runbook. It will be the Python-generated description or a default one if no Python-generated runbook is available.
	DestinationOverride []string  `dynamodbav:"destinationOverride,stringset"` // The alert destinationOverride. It will be the Python-generated description or a default one if no Python-generated destinationOverride is available.
	AlertDedupEvent
}

func FromDynamodDBAttribute(input map[string]events.DynamoDBAttributeValue) (event *AlertDedupEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = errors.Wrap(err, "panicked while getting alert dedup event")
			}
		}
	}()

	if input == nil {
		return nil, nil
	}

	ruleID, err := getAttribute("ruleId", input)
	if err != nil {
		return nil, err
	}

	ruleVersion, err := getAttribute("ruleVersion", input)
	if err != nil {
		return nil, err
	}

	deduplicationString, err := getAttribute("dedup", input)
	if err != nil {
		return nil, err
	}

	alertCount, err := getIntegerAttribute("alertCount", input)
	if err != nil {
		return nil, err
	}

	alertCreationEpoch, err := getIntegerAttribute("alertCreationTime", input)
	if err != nil {
		return nil, err
	}

	alertUpdateEpoch, err := getIntegerAttribute("alertUpdateTime", input)
	if err != nil {
		return nil, err
	}

	eventCount, err := getIntegerAttribute("eventCount", input)
	if err != nil {
		return nil, err
	}

	logTypes, err := getAttribute("logTypes", input)
	if err != nil {
		return nil, err
	}

	result := &AlertDedupEvent{
		RuleID:              ruleID.String(),
		RuleVersion:         ruleVersion.String(),
		DeduplicationString: deduplicationString.String(),
		AlertCount:          alertCount,
		CreationTime:        time.Unix(alertCreationEpoch, 0).UTC(),
		UpdateTime:          time.Unix(alertUpdateEpoch, 0).UTC(),
		EventCount:          eventCount,
		LogTypes:            logTypes.StringSet(),
	}

	alertContext := getOptionalAttribute("context", input)
	if alertContext != nil {
		result.AlertContext = aws.String(alertContext.String())
	}

	// Custom Fields
	generatedTitle := getOptionalAttribute("title", input)
	if generatedTitle != nil {
		result.GeneratedTitle = aws.String(generatedTitle.String())
	}

	generatedDescription := getOptionalAttribute("description", input)
	if generatedDescription != nil {
		result.GeneratedDescription = aws.String(generatedDescription.String())
	}

	generatedReference := getOptionalAttribute("reference", input)
	if generatedReference != nil {
		result.GeneratedReference = aws.String(generatedReference.String())
	}

	generatedSeverity := getOptionalAttribute("severity", input)
	if generatedSeverity != nil {
		result.GeneratedSeverity = aws.String(generatedSeverity.String())
	}

	generatedRunbook := getOptionalAttribute("runbook", input)
	if generatedRunbook != nil {
		result.GeneratedRunbook = aws.String(generatedRunbook.String())
	}

	generatedDestinationOverride := getOptionalAttribute("destinationOverride", input)
	if generatedDestinationOverride != nil {
		result.GeneratedDestinationOverride = generatedDestinationOverride.StringSet()
	}

	// End Custom Fields

	alertType := getOptionalAttribute("type", input)
	if alertType != nil {
		result.Type = alertType.String()
	}

	return result, nil
}

func getIntegerAttribute(key string, input map[string]events.DynamoDBAttributeValue) (int64, error) {
	value, err := getAttribute(key, input)
	if err != nil {
		return 0, err
	}
	integerValue, err := value.Integer()
	if err != nil {
		return 0, errors.Wrapf(err, "failed to convert attribute '%s' to integer", key)
	}
	return integerValue, nil
}

func getAttribute(key string, inputMap map[string]events.DynamoDBAttributeValue) (events.DynamoDBAttributeValue, error) {
	attributeValue, ok := inputMap[key]
	if !ok {
		return events.DynamoDBAttributeValue{}, errors.Errorf("could not find '%s' attribute", key)
	}
	return attributeValue, nil
}

func getOptionalAttribute(key string, inputMap map[string]events.DynamoDBAttributeValue) *events.DynamoDBAttributeValue {
	attributeValue, ok := inputMap[key]
	if !ok {
		return nil
	}
	return &attributeValue
}
