package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import eu.jsentinel.jcustos.events.store.InMemoryEnvelopeStore;
import eu.jsentinel.jcustos.events.store.JCustosEventCursor;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("DefaultJCustosEventBus — envelope tap (subscribeEnvelope)")
class DefaultJCustosEventBusEnvelopeTapTest {

  private DefaultJCustosEventBus bus(InMemoryEnvelopeStore store) {
    BusFixtures fx = new BusFixtures();
    return new DefaultJCustosEventBus(fx.publishPipeline(), store,
        ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run, () -> BusFixtures.T0);
  }

  @Test
  @DisplayName("the tap receives exactly the envelope appended to the store (record equality)")
  void tapReceivesAppendedEnvelope() {
    InMemoryEnvelopeStore store = new InMemoryEnvelopeStore();
    DefaultJCustosEventBus bus = bus(store);
    List<SignedJCustosEventEnvelope> tapped = new ArrayList<>();
    bus.subscribeEnvelope(tapped::add);

    bus.publish(BusFixtures.event());

    List<StoredEnvelope> stored = store.findAfter(JCustosEventCursor.start(), 10);
    assertEquals(1, stored.size());
    assertEquals(1, tapped.size());
    assertEquals(stored.get(0).envelope(), tapped.get(0));
  }

  @Test
  @DisplayName("the tap also fans out without an envelope store")
  void tapWorksWithoutStore() {
    DefaultJCustosEventBus bus = bus(null);
    List<SignedJCustosEventEnvelope> tapped = new ArrayList<>();
    bus.subscribeEnvelope(tapped::add);

    bus.publish(BusFixtures.event());

    assertEquals(1, tapped.size());
    assertEquals(LoginSucceededEvent.TYPE, tapped.get(0).eventType());
  }

  @Test
  @DisplayName("fan-out runs after the store append and before typed dispatch")
  void fanOutRunsBeforeTypedDispatch() {
    DefaultJCustosEventBus bus = bus(null);
    List<String> order = new ArrayList<>();
    bus.subscribeEnvelope(envelope -> order.add("tap"));
    bus.subscribe(LoginSucceededEvent.class, event -> order.add("listener"));

    bus.publish(BusFixtures.event());

    assertEquals(List.of("tap", "listener"), order);
  }

  @Test
  @DisplayName("a throwing publisher is isolated: publish succeeds, siblings and listeners run, "
      + "the failure count increments")
  void throwingPublisherIsIsolated() {
    DefaultJCustosEventBus bus = bus(null);
    List<SignedJCustosEventEnvelope> tapped = new ArrayList<>();
    AtomicInteger listened = new AtomicInteger();
    bus.subscribeEnvelope(envelope -> {
      throw new IllegalStateException("tap boom");
    });
    bus.subscribeEnvelope(tapped::add);
    bus.subscribe(LoginSucceededEvent.class, event -> listened.incrementAndGet());

    assertDoesNotThrow(() -> bus.publish(BusFixtures.event()));

    assertEquals(1, tapped.size());
    assertEquals(1, listened.get());
    assertEquals(1, bus.envelopePublisherFailureCount());
  }

  @Test
  @DisplayName("closing a registration detaches only that tap, at most once — the same "
      + "publisher registered twice stays separable")
  void registrationsAreSeparableAndIdempotent() {
    DefaultJCustosEventBus bus = bus(null);
    List<SignedJCustosEventEnvelope> tapped = new ArrayList<>();
    SignedEnvelopePublisher publisher = tapped::add;
    Registration first = bus.subscribeEnvelope(publisher);
    Registration second = bus.subscribeEnvelope(publisher);

    bus.publish(BusFixtures.event());
    assertEquals(2, tapped.size());

    first.close();
    bus.publish(BusFixtures.event());
    assertEquals(3, tapped.size());

    // closing the same registration again must not detach the sibling entry
    first.close();
    bus.publish(BusFixtures.event());
    assertEquals(4, tapped.size());

    second.close();
    bus.publish(BusFixtures.event());
    assertEquals(4, tapped.size());
  }
}
