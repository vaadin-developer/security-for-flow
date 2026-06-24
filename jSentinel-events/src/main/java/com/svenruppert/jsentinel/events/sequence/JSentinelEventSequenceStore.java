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

  /**
   * Atomically reserves and returns the next sequence for the scope: reads the
   * current last sequence, advances it ({@link EventSequence#next()}, or
   * {@link EventSequence#FIRST} for a fresh scope), persists it and returns the
   * reserved value — as one indivisible step.
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic: it
   * composes {@link #lastSequence} and {@link #updateSequence}, so two threads
   * publishing for the same {@code (tenant, producer)} can read the same last
   * value and reserve the same next one. Concurrent implementations
   * <strong>must</strong> override this method so a reserved sequence is always
   * scope-unique (R011). The shipped in-memory and Eclipse-Store stores
   * override it atomically.</p>
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @return the freshly reserved, scope-unique next sequence
   * @since 00.75.20
   */
  default EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
    EventSequence next = lastSequence(tenantId, producerId)
        .map(EventSequence::next)
        .orElse(EventSequence.FIRST);
    updateSequence(tenantId, producerId, next);
    return next;
  }
}
