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
import { FastField, useFormikContext, Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import {
  Text,
  Flex,
  Box,
  SimpleGrid,
  FormHelperText,
  Link,
  FormError,
  useSnackbar,
} from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';
import { capitalize, minutesToString } from 'Helpers/utils';
import FormikTextArea from 'Components/fields/TextArea';
import FormikSwitch from 'Components/fields/Switch';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikNumberInput from 'Components/fields/NumberInput';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { RESOURCE_TYPES } from 'Source/constants';
import { RuleFormValues } from 'Components/forms/RuleForm';
import { PolicyFormValues } from 'Components/forms/PolicyForm';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import { useListAvailableLogTypes } from 'Source/graphql/queries';
import useListAvailableDestinations from '../useListAvailableDestinations';

interface BaseRuleFormCoreSectionProps {
  type: 'rule' | 'policy';
}

const severityOptions = Object.values(SeverityEnum);
const severityItemToString = (severity: string) => capitalize(severity.toLowerCase());
const dedupPeriodMinutesOptions = [15, 30, 60, 180, 720, 1440];

const BaseRuleFormCoreSection: React.FC<BaseRuleFormCoreSectionProps> = ({ type }) => {
  const isPolicy = type === 'policy';

  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { values, initialValues } = useFormikContext<RuleFormValues | PolicyFormValues>();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    skip: isPolicy,
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  const tagAdditionValidation = React.useMemo(() => (tag: string) => !values.tags.includes(tag), [
    values.tags,
  ]);

  const {
    loading: destinationsLoading,
    destinationOutputIds: availableOutputIds,
    destinationIdToDisplayName: destIdToDisplayName,
    validOutputIds: listValidOutputIds,
    disabled: disableDestinationField,
    error: destinationsError,
  } = useListAvailableDestinations({
    outputIds: values.outputIds,
  });

  const generateHelperText = React.useCallback(() => {
    if (destinationsError) {
      return (
        <FormError id="outputIds-description" mt={2}>
          There was a problem loading your destinations!
        </FormError>
      );
    }
    if (!availableOutputIds.length && !destinationsLoading) {
      return (
        <FormHelperText id="outputIds-description" mt={2} mr={1}>
          You have not configured any destinations, create one
          <Link ml={1} as={RRLink} to={urls.settings.destinations.create()}>
            here
          </Link>
        </FormHelperText>
      );
    }
    if (destinationsLoading) {
      return (
        <FormHelperText id="outputIds-description" mt={2}>
          Loading your destinations...
        </FormHelperText>
      );
    }
    return (
      <FormHelperText id="outputIds-description" mt={2}>
        Send alerts to these destinations regardless of their severity level settings
      </FormHelperText>
    );
  }, [destinationsError, destinationsLoading, availableOutputIds]);

  const destinationHelperText = React.useMemo(() => generateHelperText(), [
    destinationsError,
    destinationsLoading,
    availableOutputIds,
  ]);

  return (
    <Box p={6}>
      <Flex spacing={5} mb={5} align="center">
        <Box>
          <Text color="navyblue-100">Basic Information</Text>
        </Box>
        <Flex spacing={6} ml="auto" mr={0} align="center" alignSelf="flex-end">
          <FastField
            as={FormikSwitch}
            name="enabled"
            label={isPolicy ? 'Policy Enabled' : 'Rule Enabled'}
          />
          <FastField
            as={FormikCombobox}
            name="severity"
            items={severityOptions}
            itemToString={severityItemToString}
            label="* Severity"
          />
        </Flex>
      </Flex>

      <SimpleGrid columns={2} spacing={5} mb={5}>
        <FastField
          as={FormikTextInput}
          label="Display Name"
          placeholder={`A human-friendly name for this ${type}`}
          name="displayName"
        />
        <FastField
          as={FormikTextInput}
          label={`* ${isPolicy ? 'Policy ID' : 'Rule ID'}`}
          placeholder={`The unique ID of this ${type}`}
          name="id"
          disabled={!!initialValues.id}
          required
        />
      </SimpleGrid>
      <SimpleGrid columns={1} spacing={5} mb={5}>
        <FastField
          as={FormikTextArea}
          label="Description"
          placeholder={`Additional context about this ${type}`}
          name="description"
        />
        <SimpleGrid columns={1} spacing={5}>
          <FastField
            as={FormikTextArea}
            label="Runbook"
            placeholder={`Procedures and operations related to this ${type}`}
            name="runbook"
          />
        </SimpleGrid>
        <Flex spacing={5}>
          <Box flexGrow={7} flexShrink={0}>
            <FastField
              as={FormikTextArea}
              label="Reference"
              placeholder={`An external link to why this ${type} exists`}
              name="reference"
            />
          </Box>
          {!isPolicy && (
            <Box flexGrow={1}>
              <Field
                as={FormikNumberInput}
                label="* Events Threshold"
                min={1}
                name="threshold"
                placeholder="Send an alert only after # events"
              />
            </Box>
          )}
        </Flex>
      </SimpleGrid>
      <Box mb={5} mt={8}>
        <Text color="navyblue-100">Additional Information</Text>
      </Box>
      <SimpleGrid columns={2} spacing={5}>
        {isPolicy && (
          <Box>
            <FastField
              as={FormikMultiCombobox}
              searchable
              label="Resource Types"
              name="resourceTypes"
              items={RESOURCE_TYPES}
              placeholder="Where should the policy apply?"
              aria-describedby="resourceTypes-description"
            />
            <FormHelperText id="resourceTypes-description" mt={2}>
              Leave empty to apply to all resources
            </FormHelperText>
          </Box>
        )}
        <FastField
          as={FormikMultiCombobox}
          searchable
          name="tags"
          label="Custom Tags"
          items={values.tags}
          allowAdditions
          validateAddition={tagAdditionValidation}
          placeholder="i.e. HIPAA (separate with <Enter>)"
        />
        {isPolicy && (
          <FastField
            as={FormikMultiCombobox}
            searchable
            name="suppressions"
            label="Ignore Patterns"
            items={(values as PolicyFormValues).suppressions}
            allowAdditions
            placeholder="i.e. aws::s3::* (separate with <Enter>)"
          />
        )}
        <Box as="fieldset">
          {/* FIXME: We have an issue with FastField here. We shouldn't be setting props like that on FastField or Field elements */}
          <Field
            as={FormikMultiCombobox}
            disabled={disableDestinationField}
            searchable
            label="Alert Destination Overrides"
            name="outputIds"
            value={listValidOutputIds}
            items={availableOutputIds}
            itemToString={destIdToDisplayName}
            placeholder="Select destinations"
            aria-describedby="outputIds-description"
          />
          {destinationHelperText}
        </Box>
        {!isPolicy && (
          <React.Fragment>
            <Field
              as={FormikMultiCombobox}
              searchable
              label="* Log Types"
              name="logTypes"
              items={data?.listAvailableLogTypes.logTypes ?? []}
              placeholder="Where should the rule appoly?"
            />
            <FastField
              as={FormikCombobox}
              label="* Deduplication Period"
              name="dedupPeriodMinutes"
              items={dedupPeriodMinutesOptions}
              itemToString={minutesToString}
            />
          </React.Fragment>
        )}
      </SimpleGrid>
    </Box>
  );
};

export default React.memo(BaseRuleFormCoreSection);
