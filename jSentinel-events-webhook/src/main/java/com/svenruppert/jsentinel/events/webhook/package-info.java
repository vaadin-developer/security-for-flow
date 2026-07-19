/*-
 * #%L
 * jSentinel Events — Webhook exporter
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
 * V00.80.00 (Konzept goal 8) webhook integration for the Security Event Bus:
 * {@link com.svenruppert.jsentinel.events.webhook.WebhookEventPublisher}
 * subscribes to the bus's envelope tap
 * ({@code JSentinelEventBus.subscribeEnvelope}) and POSTs every signed
 * envelope — in the {@code EnvelopeWireCodec} wire form shared with the
 * REST/SSE bridge — to an operator-configured endpoint. The signed envelope
 * IS the authenticity and integrity layer; receivers verify it with the
 * events verification SPIs, which is why this module deliberately adds no
 * transport-level HMAC. Opt-in: nothing in this module is registered or
 * started unless the application wires a publisher explicitly.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.events.webhook;
