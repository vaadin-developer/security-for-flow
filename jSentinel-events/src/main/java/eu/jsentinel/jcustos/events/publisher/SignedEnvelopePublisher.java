package eu.jsentinel.jcustos.events.publisher;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;

/**
 * Envelope tap: receives every signed envelope the bus publishes, after the
 * envelope-store append (when a store is configured), on the <em>publish
 * thread</em>, synchronously.
 *
 * <p>Because delivery is synchronous on the publish thread, implementations
 * must be fast or hand off internally (see
 * {@code EventStreamPublisher} for a ready-made asynchronous hand-off). A
 * {@link RuntimeException} thrown by an implementation is isolated by the bus
 * — logged and counted — and never breaks the publish.
 *
 * <p>The signature is deliberately envelope-only (no cursor): consumers that
 * need resume semantics use
 * {@link eu.jsentinel.jcustos.events.store.JSentinelEventEnvelopeStore#findAfter}.
 *
 * @since 00.80.00
 */
@FunctionalInterface
@ExperimentalJSentinelApi
public interface SignedEnvelopePublisher {

  /**
   * Handles one published signed envelope.
   *
   * @param envelope the signed envelope
   */
  void onEnvelope(SignedJSentinelEventEnvelope envelope);
}
