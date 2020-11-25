// Code generated by go-swagger; DO NOT EDIT.

package operations

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

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// ListRulesReader is a Reader for the ListRules structure.
type ListRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListRulesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListRulesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewListRulesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListRulesOK creates a ListRulesOK with default headers values
func NewListRulesOK() *ListRulesOK {
	return &ListRulesOK{}
}

/*ListRulesOK handles this case with default header values.

OK
*/
type ListRulesOK struct {
	Payload *models.RuleList
}

func (o *ListRulesOK) Error() string {
	return fmt.Sprintf("[GET /rule/list][%d] listRulesOK  %+v", 200, o.Payload)
}

func (o *ListRulesOK) GetPayload() *models.RuleList {
	return o.Payload
}

func (o *ListRulesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RuleList)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRulesBadRequest creates a ListRulesBadRequest with default headers values
func NewListRulesBadRequest() *ListRulesBadRequest {
	return &ListRulesBadRequest{}
}

/*ListRulesBadRequest handles this case with default header values.

Bad request
*/
type ListRulesBadRequest struct {
	Payload *models.Error
}

func (o *ListRulesBadRequest) Error() string {
	return fmt.Sprintf("[GET /rule/list][%d] listRulesBadRequest  %+v", 400, o.Payload)
}

func (o *ListRulesBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListRulesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRulesInternalServerError creates a ListRulesInternalServerError with default headers values
func NewListRulesInternalServerError() *ListRulesInternalServerError {
	return &ListRulesInternalServerError{}
}

/*ListRulesInternalServerError handles this case with default header values.

Internal server error
*/
type ListRulesInternalServerError struct {
}

func (o *ListRulesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /rule/list][%d] listRulesInternalServerError ", 500)
}

func (o *ListRulesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}