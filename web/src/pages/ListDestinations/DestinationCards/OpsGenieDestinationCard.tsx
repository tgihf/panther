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
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum, OpsgenieServiceRegionEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface OpsGenieDestinationCardProps {
  destination: DestinationFull;
}

const OpsGenieDestinationCard: React.FC<OpsGenieDestinationCardProps> = ({ destination }) => {
  return (
    <DestinationCard
      logo={DESTINATIONS[DestinationTypeEnum.Opsgenie].logo}
      destination={destination}
    >
      <GenericItemCard.Value
        label="Service Region"
        value={
          destination.outputConfig.opsgenie.serviceRegion === OpsgenieServiceRegionEnum.Eu
            ? 'European'
            : 'American (Default)'
        }
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Date Created"
        value={formatDatetime(destination.creationTime, true)}
      />
      <GenericItemCard.Value
        label="Last Updated"
        value={formatDatetime(destination.lastModifiedTime, true)}
      />
    </DestinationCard>
  );
};

export default React.memo(OpsGenieDestinationCard);
