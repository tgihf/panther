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
import { Alert, Box, Flex } from 'pouncejs';
import Panel from 'Components/Panel';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import LinkButton from 'Components/buttons/LinkButton';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import TablePlaceholder from 'Components/TablePlaceholder';
import EmptyDataFallback from './EmptyDataFallback';
import { useListDataModels } from './graphql/listDataModels.generated';
import DataModelCard from './DataModelCard';

const ListDataModels = () => {
  useTrackPageView(PageViewEnum.ListDataModels);

  const { loading, error, data } = useListDataModels({ variables: { input: {} } });

  const dataModels = data?.listDataModels?.models;
  return (
    <Box mb={6}>
      <Panel
        title="Data Models"
        actions={
          <LinkButton to={urls.logAnalysis.dataModels.create()} icon="add">
            Add new
          </LinkButton>
        }
      >
        <ErrorBoundary>
          {loading && <TablePlaceholder />}
          {error && (
            <Alert
              variant="error"
              title="Couldn't load your data models"
              description={
                extractErrorMessage(error) ||
                'There was an error while attempting to list your data models'
              }
            />
          )}
          {dataModels &&
            (dataModels.length > 0 ? (
              <Flex direction="column" spacing={2}>
                {dataModels.map(dataModel => (
                  <DataModelCard key={dataModel.id} dataModel={dataModel} />
                ))}
              </Flex>
            ) : (
              <EmptyDataFallback />
            ))}
        </ErrorBoundary>
      </Panel>
    </Box>
  );
};

export default withSEO({ title: 'Data Models' })(ListDataModels);
