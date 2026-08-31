/*-
 * #%L
 * jSentinel Events — OpenTelemetry exporter
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
 * V00.80.00 (Konzept goal 8) OpenTelemetry integration for the Security
 * Event Bus:
 * {@link eu.jsentinel.jcustos.events.otel.OpenTelemetryEventPublisher}
 * subscribes to the bus's envelope tap and maps every signed envelope to one
 * OpenTelemetry <em>log record</em> over the Logs Bridge API.
 *
 * <p>Signal choice: a security event is a discrete occurrence — a span would
 * fabricate duration and trace semantics it does not have, and metrics are
 * the {@code jSentinel-monitoring} bridge's territory. The Logs Bridge API
 * ships inside {@code opentelemetry-api}, so this module is
 * <strong>api-only at compile scope</strong> and noop-safe by construction:
 * with {@code LoggerProvider.noop()} every call is free and silent. Opt-in:
 * nothing is registered unless the application wires the publisher.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.events.otel;
