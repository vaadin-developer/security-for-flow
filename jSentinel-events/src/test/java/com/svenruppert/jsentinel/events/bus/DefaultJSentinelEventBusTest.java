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

import com.svenruppert.jsentinel.events.types.ListenerFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.RoleAssignedEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("DefaultJSentinelEventBus")
class DefaultJSentinelEventBusTest {

  private DefaultJSentinelEventBus bus(ListenerErrorStrategy strategy) {
    BusFixtures fx = new BusFixtures();
    return new DefaultJSentinelEventBus(fx.publishPipeline(), null, strategy,
        Runnable::run, () -> BusFixtures.T0);
  }

  @Test
  @DisplayName("publish delivers to a subscribed listener; closing the registration stops it")
  void subscribeAndUnsubscribe() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger count = new AtomicInteger();
    Registration reg = bus.subscribe(LoginSucceededEvent.class, e -> count.incrementAndGet());

    bus.publish(BusFixtures.event());
    assertEquals(1, count.get());

    reg.close();
    bus.publish(BusFixtures.event());
    assertEquals(1, count.get());
  }

  @Test
  @DisplayName("listeners only receive events of their subscribed type")
  void typeFiltering() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger roleCount = new AtomicInteger();
    bus.subscribe(RoleAssignedEvent.class, e -> roleCount.incrementAndGet());
    bus.publish(BusFixtures.event()); // a LoginSucceededEvent
    assertEquals(0, roleCount.get());
  }

  @Test
  @DisplayName("ISOLATE_AND_CONTINUE: a failing listener does not stop others and is reported")
  void isolateAndContinue() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger secondCount = new AtomicInteger();
    AtomicReference<ListenerFailedEvent> reported = new AtomicReference<>();

    bus.subscribe(LoginSucceededEvent.class, e -> {
      throw new IllegalStateException("boom");
    });
    bus.subscribe(LoginSucceededEvent.class, e -> secondCount.incrementAndGet());
    bus.subscribe(ListenerFailedEvent.class, reported::set);

    bus.publish(BusFixtures.event());

    assertEquals(1, secondCount.get(), "second listener still ran");
    assertNotNull(reported.get(), "a ListenerFailed event was reported");
    assertEquals("IllegalStateException", reported.get().failureCode());
  }

  @Test
  @DisplayName("ABORT_ON_FIRST_ERROR: a listener failure propagates from publish")
  void abortOnFirstError() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ABORT_ON_FIRST_ERROR);
    bus.subscribe(LoginSucceededEvent.class, e -> {
      throw new IllegalStateException("boom");
    });
    assertThrows(IllegalStateException.class, () -> bus.publish(BusFixtures.event()));
  }

  @Test
  @DisplayName("a critical listener failure propagates even under ISOLATE_AND_CONTINUE")
  void criticalListenerPropagates() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    bus.subscribe(LoginSucceededEvent.class, JSentinelEventListenerOptions.criticalListener(),
        e -> {
          throw new IllegalStateException("critical boom");
        });
    assertThrows(IllegalStateException.class, () -> bus.publish(BusFixtures.event()));
  }

  @Test
  @DisplayName("publishAsync runs the pipeline and dispatches")
  void publishAsync() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger count = new AtomicInteger();
    bus.subscribe(LoginSucceededEvent.class, e -> count.incrementAndGet());
    bus.publishAsync(BusFixtures.event()).toCompletableFuture().join();
    assertEquals(1, count.get());
  }
}
