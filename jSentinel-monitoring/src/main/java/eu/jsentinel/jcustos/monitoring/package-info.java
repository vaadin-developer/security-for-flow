/*-
 * #%L
 * jCustos Monitoring — metrics, health and diagnostics export points
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
 * V00.80 operational-monitoring module (Konzept-V00.80.00 goal 9,
 * "Betrieb &amp; Forensik"): clean export points so production systems
 * can be observed — <em>no monitoring stack is bundled</em>.
 *
 * <p>The module ships framework-neutral SPIs plus the metric-name
 * catalog; concrete exporters (Micrometer, OpenTelemetry, Prometheus,
 * StatsD) live in adapters that plug in via {@code META-INF/services}
 * or programmatic wiring. Without such an adapter every export point
 * degrades to a zero-cost no-op.</p>
 *
 * <p>Every public type is annotated {@link
 * eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi}.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.monitoring;
