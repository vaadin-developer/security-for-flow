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

/**
 * V00.80 envelope tap + in-tree publishers (Konzept goal 8): the {@link
 * eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher} SPI
 * receives every signed envelope the bus publishes, and this package ships
 * the in-tree implementations — {@link
 * eu.jsentinel.jcustos.events.publisher.LoggingEventPublisher} (stable
 * one-line-per-envelope log stream), {@link
 * eu.jsentinel.jcustos.events.publisher.EventStreamPublisher}
 * (in-process {@link java.util.concurrent.Flow} tap for embedding apps) —
 * plus the alerting building blocks {@link
 * eu.jsentinel.jcustos.events.publisher.JCustosAlert}, {@link
 * eu.jsentinel.jcustos.events.publisher.JCustosAlertSink}, {@link
 * eu.jsentinel.jcustos.events.publisher.LoggingAlertSink} and the
 * severity-filtering {@link
 * eu.jsentinel.jcustos.events.publisher.JCustosAlertPublisher}.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.events.publisher;
