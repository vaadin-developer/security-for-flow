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

/**
 * V00.80 envelope tap + in-tree publishers (Konzept goal 8): the {@link
 * com.svenruppert.jsentinel.events.publisher.SignedEnvelopePublisher} SPI
 * receives every signed envelope the bus publishes, and this package ships
 * the in-tree implementations — {@link
 * com.svenruppert.jsentinel.events.publisher.LoggingEventPublisher} (stable
 * one-line-per-envelope log stream), {@link
 * com.svenruppert.jsentinel.events.publisher.EventStreamPublisher}
 * (in-process {@link java.util.concurrent.Flow} tap for embedding apps) —
 * plus the alerting building blocks {@link
 * com.svenruppert.jsentinel.events.publisher.JSentinelAlert}, {@link
 * com.svenruppert.jsentinel.events.publisher.JSentinelAlertSink}, {@link
 * com.svenruppert.jsentinel.events.publisher.LoggingAlertSink} and the
 * severity-filtering {@link
 * com.svenruppert.jsentinel.events.publisher.JSentinelAlertPublisher}.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.events.publisher;
