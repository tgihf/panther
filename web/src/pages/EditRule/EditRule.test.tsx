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

import React from 'react';
import {
  render,
  fireEvent,
  waitForElementToBeRemoved,
  waitFor,
  buildDetectionTestDefinition,
  buildRuleDetails,
} from 'test-utils';
import urls from 'Source/urls';
import { Route } from 'react-router-dom';
import { mockRuleDetails } from './graphql/ruleDetails.generated';
import EditRule from './EditRule';

describe('EditRule', () => {
  it('renders the initial tabs and fields', async () => {
    // Tests should get overriden as the component expects a string in JSON format.
    const tests = [
      buildDetectionTestDefinition({
        resource: '{"CreateDate":"2019-01-01T00:00:00Z"}',
      }),
    ];
    const rule = buildRuleDetails({ tests });

    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: rule.id,
          },
        },
      }),
    ];
    const { getByTestId, getByText, getByLabelText } = render(
      <Route exact path={urls.logAnalysis.rules.edit(':id')}>
        <EditRule />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.rules.edit(rule.id),
      }
    );

    const loadingInterfaceElement = getByTestId('rule-edit-loading');

    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Fields
    expect(getByText('Rule Enabled')).toBeInTheDocument();
    expect(getByText('* Severity')).toBeInTheDocument();
    expect(getByLabelText('Display Name')).toBeInTheDocument();
    expect(getByLabelText('* Rule ID')).toBeInTheDocument();
    expect(getByLabelText('Description')).toBeInTheDocument();
    expect(getByLabelText('Runbook')).toBeInTheDocument();
    expect(getByLabelText('Reference')).toBeInTheDocument();
    expect(getByText('Custom Tags')).toBeInTheDocument();
    expect(getByText('Alert Destination Overrides')).toBeInTheDocument();
    expect(getByText('* Log Types')).toBeInTheDocument();
    expect(getByText('* Deduplication Period')).toBeInTheDocument();

    // Helper text
    expect(getByText('Basic Information')).toBeInTheDocument();
    expect(getByText('Additional Information')).toBeInTheDocument();

    // Tabs
    expect(getByText('Policy Settings')).toBeInTheDocument();
    expect(getByText('Functions & Tests')).toBeInTheDocument();
  });

  it('renders the function and tests tab', async () => {
    // Tests should get overriden as the component expects a string in JSON format.
    const tests = [
      buildDetectionTestDefinition({
        resource: '{"CreateDate":"2019-01-01T00:00:00Z"}',
      }),
    ];
    const rule = buildRuleDetails({ tests });

    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: rule.id,
          },
        },
      }),
    ];
    const { getByTestId, getByText, getByAriaLabel } = render(
      <Route exact path={urls.logAnalysis.rules.edit(':id')}>
        <EditRule />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.rules.edit(rule.id),
      }
    );

    const loadingInterfaceElement = getByTestId('rule-edit-loading');

    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Fields
    fireEvent.click(getByText('Functions & Tests'));

    await waitFor(() => {
      expect(getByText('Rule Function')).toBeInTheDocument();
    });
    expect(getByAriaLabel('Create test')).toBeInTheDocument();
    expect(getByAriaLabel('Run Test')).toBeInTheDocument();
    expect(getByAriaLabel('Run All')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Editor visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Tests visibility')).toBeInTheDocument();
  });
});
