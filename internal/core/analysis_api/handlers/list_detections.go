package handlers

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
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// TODO include policy & shared stuff
func (API) ListDetections(input *models.ListDetectionsInput) *events.APIGatewayProxyResponse {
	projectComplianceStatus := stdDetectionListInput(input)

	// Scan dynamo
	scanInput, err := detectionScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []tableItem
	compliance := make(map[string]complianceStatus)

	// We need to include compliance status in the response if the user asked for it
	// (or if they left the input.Fields blank, which defaults to all fields)

	err = scanPages(scanInput, func(item tableItem) error {
		zap.L().Info("considering item", zap.Any("item", item))
		// Fetch the compliance status if we need it for the filter or projection
		if item.Type == models.TypePolicy && (projectComplianceStatus || input.ComplianceStatus != "") {
			status, err := getComplianceStatus(item.ID) // compliance-api
			if err != nil {
				return err
			}
			zap.L().Info("adding status", zap.String("policy", item.ID), zap.Any("status", *status))
			compliance[item.ID] = *status
		}

		if input.ComplianceStatus != "" && input.ComplianceStatus != compliance[item.ID].Status {
			zap.L().Info("compliance status does not pass projection", zap.String("policy", item.ID))
			return nil // compliance status does not match filter: skip
		}

		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan detections", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sort and page
	// TODO make sure this includes policy & new
	sortItems(items, input.SortBy, input.SortDir, nil)
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListDetectionsOutput{
		Detections: make([]models.Detection, 0, len(items)),
		Paging:     paging,
	}
	for _, item := range items {
		if projectComplianceStatus && item.Type == models.TypePolicy {
			status := compliance[item.ID].Status
			result.Detections = append(result.Detections, *item.Detection(&status))
		}
		result.Detections = append(result.Detections, *item.Detection(nil))
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

// Set defaults and standardize input request
func stdDetectionListInput(input *models.ListDetectionsInput) bool {
	input.NameContains = strings.ToLower(input.NameContains)
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	if input.SortBy == "" {
		input.SortBy = "displayName"
	}
	if input.SortDir == "" {
		input.SortDir = defaultSortDir
	}
	if len(input.AnalysisTypes) == 0 {
		input.AnalysisTypes = []models.DetectionType{models.TypePolicy, models.TypeRule}
	}
	// If a compliance status was specified, we can only query policies.
	// This is a unique field because we look it up from another table. For other fields (such as
	// suppressions for policies or dedup period for rules) we don't need this logic because if the
	// user filters on this field it will automatically exclude everything of the wrong type.
	if input.ComplianceStatus != "" {
		zap.L().Info("setting analysis type filter to policies only since compliance status filter is set")
		input.AnalysisTypes = []models.DetectionType{models.TypePolicy}
	}

	idPresent, typePresent := false, false
	statusProjection := len(input.Fields) == 0
	for _, field := range input.Fields {
		if field == "complianceStatus" {
			statusProjection = true
		}
		if field == "id" {
			idPresent = true
		}
		if field == "type" {
			typePresent = true
		}
		if idPresent && typePresent && statusProjection {
			break
		}
	}
	if statusProjection || input.ComplianceStatus != "" {
		if !idPresent {
			input.Fields = append(input.Fields, "id")
		}
		if !typePresent {
			input.Fields = append(input.Fields, "type")
		}
		zap.L().Info("compliance is required")
	}

	return statusProjection
}

// TODO: check if we need to copy in any policy logic or new logic
func detectionScanInput(input *models.ListDetectionsInput) (*dynamodb.ScanInput, error) {
	listFilters := pythonFilters{
		CreatedBy:      input.CreatedBy,
		Enabled:        input.Enabled,
		InitialSet:     input.InitialSet,
		LastModifiedBy: input.LastModifiedBy,
		NameContains:   input.NameContains,
		Severity:       input.Severity,
		ResourceTypes:  input.Types,
		Tags:           input.Tags,
	}

	filters := pythonListFilters(&listFilters)
	if input.HasRemediation != nil {
		if *input.HasRemediation {
			// We only want policies with a remediation specified
			filters = append(filters, expression.AttributeExists(expression.Name("autoRemediationId")))
		} else {
			// We only want policies without a remediation id
			filters = append(filters, expression.AttributeNotExists(expression.Name("autoRemediationId")))
		}
	}

	return buildScanInput(input.AnalysisTypes, input.Fields, filters...)
}
