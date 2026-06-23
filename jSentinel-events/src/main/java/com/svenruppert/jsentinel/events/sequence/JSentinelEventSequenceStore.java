package com.svenruppert.jsentinel.events.sequence;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;

import java.util.Optional;

/**
 * Sequence store (Konzept §652): tracks the last accepted monotone sequence per
 * {@code tenantId + producerId}, so a consumer can detect gaps, repeats and
 * roll-backs.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventSequenceStore {

  /**
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @return the last accepted sequence for the scope, if any
   */
  Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId);

  /**
   * Atomically updates the last accepted sequence for the scope.
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @param sequence the new last-accepted sequence
   */
  void updateSequence(TenantId tenantId, EventProducerId producerId, EventSequence sequence);
}
