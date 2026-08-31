package eu.jsentinel.jcustos.events.replay;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;

import java.time.Instant;

/**
 * Replay-protection store (Konzept §639). A validly signed envelope must not be
 * processable an unbounded number of times.
 *
 * <p>{@link #markSeen(EventEnvelopeId, Instant)} MUST be atomic: under
 * concurrent processing, exactly one consumer may mark a given envelope as seen
 * (Konzept §646).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventReplayStore {

  /**
   * Atomically records that an envelope has been seen.
   *
   * @param envelopeId the envelope identity
   * @param expiresAt when the entry may be purged
   * @return {@code true} if this call was the first to mark the envelope,
   *     {@code false} if it had already been seen
   */
  boolean markSeen(EventEnvelopeId envelopeId, Instant expiresAt);

  /**
   * @param envelopeId the envelope identity
   * @return {@code true} if the envelope has already been marked seen
   */
  boolean hasSeen(EventEnvelopeId envelopeId);

  /**
   * Removes entries whose expiry is at or before {@code now}.
   *
   * @param now the current instant
   */
  void purgeExpired(Instant now);
}
