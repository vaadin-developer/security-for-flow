package eu.jsentinel.jcustos.events.integration;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.bus.JSentinelEventBus;
import eu.jsentinel.jcustos.events.bus.JSentinelEventListener;
import eu.jsentinel.jcustos.events.bus.JSentinelEventListenerOptions;
import eu.jsentinel.jcustos.events.bus.Registration;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import eu.jsentinel.jcustos.events.types.SessionRevokedEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("FeatureFlaggedEventPublisher")
class FeatureFlaggedEventPublisherTest {

  /** A real recording bus — not a mock. */
  private static final class RecordingBus implements JSentinelEventBus {
    final List<JSentinelEvent> published = new ArrayList<>();

    @Override
    public void publish(JSentinelEvent event) {
      published.add(event);
    }

    @Override
    public CompletionStage<Void> publishAsync(JSentinelEvent event) {
      publish(event);
      return CompletableFuture.completedFuture(null);
    }

    @Override
    public <E extends JSentinelEvent> Registration subscribe(
        Class<E> eventType, JSentinelEventListener<? super E> listener) {
      return () -> { };
    }

    @Override
    public <E extends JSentinelEvent> Registration subscribe(
        Class<E> eventType, JSentinelEventListenerOptions options,
        JSentinelEventListener<? super E> listener) {
      return () -> { };
    }

    @Override
    public Registration subscribeEnvelope(SignedEnvelopePublisher publisher) {
      return () -> { };
    }
  }

  private static JSentinelEvent event() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        Instant.parse("2026-06-24T10:00:00Z"), JSentinelEventSeverity.WARNING);
    return new SessionRevokedEvent(meta, "sid-1", "admin-revoked");
  }

  @Test
  @DisplayName("emission is skipped when the flag is off")
  void skippedWhenDisabled() {
    RecordingBus bus = new RecordingBus();
    FeatureFlaggedEventPublisher publisher = new FeatureFlaggedEventPublisher(bus, () -> false);
    assertFalse(publisher.publishIfEnabled(event()));
    assertTrue(bus.published.isEmpty());
  }

  @Test
  @DisplayName("the event is published when the flag is on")
  void publishedWhenEnabled() {
    RecordingBus bus = new RecordingBus();
    FeatureFlaggedEventPublisher publisher = new FeatureFlaggedEventPublisher(bus, () -> true);
    assertTrue(publisher.publishIfEnabled(event()));
    assertEquals(1, bus.published.size());
  }

  @Test
  @DisplayName("the feature flag defaults to disabled")
  void flagDefaultsDisabled() {
    String previous = System.getProperty(JSentinelEventBusFeatureFlag.PROPERTY);
    System.clearProperty(JSentinelEventBusFeatureFlag.PROPERTY);
    try {
      assertFalse(JSentinelEventBusFeatureFlag.enabled());
    } finally {
      if (previous != null) {
        System.setProperty(JSentinelEventBusFeatureFlag.PROPERTY, previous);
      }
    }
  }
}
