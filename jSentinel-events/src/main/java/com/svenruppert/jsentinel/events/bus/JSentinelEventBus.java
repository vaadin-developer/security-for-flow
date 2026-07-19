package com.svenruppert.jsentinel.events.bus;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.publisher.SignedEnvelopePublisher;

import java.util.concurrent.CompletionStage;

/**
 * The Security Event Bus API (Konzept §791). Publishing wraps an event into a
 * signed envelope (the publish pipeline) and dispatches it to local listeners;
 * subscribing registers a typed listener.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventBus {

  /**
   * Publishes an event synchronously.
   *
   * @param event the event to publish
   */
  void publish(JSentinelEvent event);

  /**
   * Publishes an event asynchronously.
   *
   * @param event the event to publish
   * @return a stage completing when the publish pipeline has run
   */
  CompletionStage<Void> publishAsync(JSentinelEvent event);

  /**
   * Subscribes a listener for a given event type with default options.
   *
   * @param eventType the event class to listen for
   * @param listener the listener
   * @param <E> the event type
   * @return a registration that unsubscribes when closed
   */
  <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType, JSentinelEventListener<? super E> listener);

  /**
   * Subscribes a listener for a given event type with explicit options.
   *
   * @param eventType the event class to listen for
   * @param options the subscription options
   * @param listener the listener
   * @param <E> the event type
   * @return a registration that unsubscribes when closed
   */
  <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType, JSentinelEventListenerOptions options,
      JSentinelEventListener<? super E> listener);

  /**
   * Subscribes an envelope tap that receives every signed envelope this bus
   * publishes — after the envelope-store append (when a store is configured),
   * on the publish thread, synchronously. Only signed-pipeline envelopes
   * reach the tap: self-observability events are dispatched directly and
   * carry no envelope, so they never fan out here.
   *
   * @param publisher the envelope tap
   * @return a registration that unsubscribes when closed
   * @since 00.80.00
   */
  Registration subscribeEnvelope(SignedEnvelopePublisher publisher);
}
