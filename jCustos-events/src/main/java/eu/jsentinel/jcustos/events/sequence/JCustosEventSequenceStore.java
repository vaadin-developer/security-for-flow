package eu.jsentinel.jcustos.events.sequence;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;

import java.util.Objects;
import java.util.Optional;

/**
 * Sequence store (Konzept §652): tracks the last accepted monotone sequence per
 * {@code tenantId + producerId}, so a consumer can detect gaps, repeats and
 * roll-backs.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventSequenceStore {

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

  /**
   * Atomically advances the last accepted sequence from {@code expectedLast} to
   * {@code newSequence} for the scope — the <em>consume-side</em> counterpart to
   * {@link #reserveNext}. If the current last sequence still equals
   * {@code expectedLast}, it is replaced by {@code newSequence} and {@code true}
   * is returned; otherwise (another thread advanced it in between) nothing is
   * changed and {@code false} is returned.
   *
   * <p>A consumer reads {@link #lastSequence}, validates the inbound sequence
   * against that observed value, then calls this method passing the same
   * observed value as {@code expectedLast}. A {@code false} result means the
   * read-validate-commit lost a race and the inbound envelope must be rejected
   * (R016, V00.76.10): there is no lost update, and the per-producer
   * monotonicity guarantee holds even when distinct envelopes claim the same
   * sequence concurrently.</p>
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic (it
   * composes {@link #lastSequence} + {@link #updateSequence}); concurrent
   * implementations <strong>must</strong> override it. The shipped in-memory and
   * Eclipse-Store stores override it atomically.</p>
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @param expectedLast the last sequence the caller observed ({@code empty} for a fresh scope)
   * @param newSequence the sequence to advance to
   * @return {@code true} iff the advance was applied atomically
   * @since 00.76.10
   */
  default boolean compareAndAdvance(TenantId tenantId, EventProducerId producerId,
      Optional<EventSequence> expectedLast, EventSequence newSequence) {
    Objects.requireNonNull(expectedLast, "expectedLast");
    Objects.requireNonNull(newSequence, "newSequence");
    if (!lastSequence(tenantId, producerId).equals(expectedLast)) {
      return false;
    }
    updateSequence(tenantId, producerId, newSequence);
    return true;
  }
}
