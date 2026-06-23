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

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory {@link JSentinelEventSequenceStore}. The per-scope counter is held
 * in a {@link ConcurrentHashMap}; updates are atomic per
 * {@code (tenantId, producerId)} key.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemorySequenceStore implements JSentinelEventSequenceStore {

  private record Scope(TenantId tenantId, EventProducerId producerId) {
  }

  private final ConcurrentMap<Scope, EventSequence> sequences = new ConcurrentHashMap<>();

  @Override
  public Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId) {
    return Optional.ofNullable(sequences.get(key(tenantId, producerId)));
  }

  @Override
  public void updateSequence(TenantId tenantId, EventProducerId producerId,
      EventSequence sequence) {
    Objects.requireNonNull(sequence, "sequence");
    sequences.put(key(tenantId, producerId), sequence);
  }

  private static Scope key(TenantId tenantId, EventProducerId producerId) {
    return new Scope(
        Objects.requireNonNull(tenantId, "tenantId"),
        Objects.requireNonNull(producerId, "producerId"));
  }
}
