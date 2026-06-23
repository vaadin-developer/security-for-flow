/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

/**
 * V00.75 REST/SSE bridge (Konzept §900-§996). Connects separate processes
 * (typically a REST service and a Vaadin app) so security-relevant envelopes
 * cross the boundary:
 *
 * <ul>
 *   <li>{@link com.svenruppert.jsentinel.events.rest.SseStreamHttpHandler} —
 *       {@code GET /api/events/stream}: replay-from-cursor + live tail via the
 *       {@link com.svenruppert.jsentinel.events.rest.SseEventBroadcaster}.</li>
 *   <li>{@link com.svenruppert.jsentinel.events.rest.EventPublishHttpHandler} —
 *       {@code POST /api/events}: permission-gated, runs the consume pipeline
 *       through the framework-light {@link
 *       com.svenruppert.jsentinel.events.rest.EventPublishService}.</li>
 *   <li>{@link com.svenruppert.jsentinel.events.rest.EnvelopeWireCodec} —
 *       envelope ⇄ flat JSON (Base64 binaries), no Jackson.</li>
 * </ul>
 *
 * <p>The bridge does not encrypt the channel — that is delegated to HTTPS /
 * mTLS (Konzept §984). Every public type is annotated {@code
 * @ExperimentalJSentinelApi}.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.rest;
