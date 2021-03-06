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

import * as Types from '../../../__generated__/schema';

import { DeliveryResponseFull } from '../fragments/DeliveryResponseFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type SendTestAlertVariables = {
  input: Types.SendTestAlertInput;
};

export type SendTestAlert = { sendTestAlert: Array<Types.Maybe<DeliveryResponseFull>> };

export const SendTestAlertDocument = gql`
  query SendTestAlert($input: SendTestAlertInput!) {
    sendTestAlert(input: $input) {
      ...DeliveryResponseFull
    }
  }
  ${DeliveryResponseFull}
`;

/**
 * __useSendTestAlert__
 *
 * To run a query within a React component, call `useSendTestAlert` and pass it any options that fit your needs.
 * When your component renders, `useSendTestAlert` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useSendTestAlert({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useSendTestAlert(
  baseOptions?: ApolloReactHooks.QueryHookOptions<SendTestAlert, SendTestAlertVariables>
) {
  return ApolloReactHooks.useQuery<SendTestAlert, SendTestAlertVariables>(
    SendTestAlertDocument,
    baseOptions
  );
}
export function useSendTestAlertLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<SendTestAlert, SendTestAlertVariables>
) {
  return ApolloReactHooks.useLazyQuery<SendTestAlert, SendTestAlertVariables>(
    SendTestAlertDocument,
    baseOptions
  );
}
export type SendTestAlertHookResult = ReturnType<typeof useSendTestAlert>;
export type SendTestAlertLazyQueryHookResult = ReturnType<typeof useSendTestAlertLazyQuery>;
export type SendTestAlertQueryResult = ApolloReactCommon.QueryResult<
  SendTestAlert,
  SendTestAlertVariables
>;
export function mockSendTestAlert({
  data,
  variables,
  errors,
}: {
  data: SendTestAlert;
  variables?: SendTestAlertVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: SendTestAlertDocument, variables },
    result: { data, errors },
  };
}
