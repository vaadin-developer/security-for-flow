/*-
 * #%L
 * jCustos Events — REST / SSE bridge
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

/**
 * V00.75 REST/SSE bridge (Konzept §900-§996). Connects separate processes
 * (typically a REST service and a Vaadin app) so security-relevant envelopes
 * cross the boundary:
 *
 * <ul>
 *   <li>{@link eu.jsentinel.jcustos.events.rest.SseStreamHttpHandler} —
 *       {@code GET /api/events/stream}: replay-from-cursor + live tail via the
 *       {@link eu.jsentinel.jcustos.events.rest.SseEventBroadcaster}.</li>
 *   <li>{@link eu.jsentinel.jcustos.events.rest.EventPublishHttpHandler} —
 *       {@code POST /api/events}: permission-gated, runs the consume pipeline
 *       through the framework-light {@link
 *       eu.jsentinel.jcustos.events.rest.EventPublishService}.</li>
 *   <li>{@link eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec} —
 *       envelope ⇄ flat JSON (Base64 binaries), no Jackson. Moved to
 *       {@code jCustos-events} in V00.80.00; the deprecated delegator at
 *       the old location was removed in V00.81.00 as announced.</li>
 * </ul>
 *
 * <p>The bridge does not encrypt the channel — that is delegated to HTTPS /
 * mTLS (Konzept §984). Every public type is annotated {@code
 * @ExperimentalJCustosApi}.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.rest;
