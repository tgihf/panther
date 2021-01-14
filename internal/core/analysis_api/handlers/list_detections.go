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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// TODO include policy & shared stuff
func (API) ListDetections(input *models.ListDetectionsInput) *events.APIGatewayProxyResponse {
	stdDetectionListInput(input)

	// Scan dynamo
	scanInput, err := detectionScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []tableItem
	err = scanPages(scanInput, func(item tableItem) error {
		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan rules", zap.Error(err))
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
		result.Detections = append(result.Detections, *item.Detection())
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

// Set defaults and standardize input request
// TODO: check if we need to copy in any policy standardizing logic or new standardizing logic
func stdDetectionListInput(input *models.ListDetectionsInput) {
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
		Tags:           input.Tags,
	}

	filters := pythonListFilters(&listFilters)
	return buildScanInput(models.TypeRule, input.Fields, filters...)
}
