package com.svenruppert.jsentinel.monitoring.metrics;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one / multiple selection rules are exercised through the
 * package-private {@link JSentinelMetricsPublishers#select(List)}
 * seam with hand-built lists — deliberately no
 * {@code META-INF/services} registration on the test classpath, so
 * {@link JSentinelMetricsPublishers#discover()} genuinely exercises
 * the empty-classpath fallback.
 */
class JSentinelMetricsPublishersTest {

  @Test
  @DisplayName("discover() without any registration returns the no-op singleton")
  void discoverWithoutRegistrationReturnsNoOp() {
    assertSame(NoOpJSentinelMetricsPublisher.INSTANCE,
        JSentinelMetricsPublishers.discover());
  }

  @Test
  @DisplayName("select() on an empty list returns the no-op singleton")
  void selectEmptyReturnsNoOp() {
    assertSame(NoOpJSentinelMetricsPublisher.INSTANCE,
        JSentinelMetricsPublishers.select(List.of()));
  }

  @Test
  @DisplayName("select() with exactly one provider returns that instance")
  void selectSingleReturnsThatInstance() {
    RecordingMetricsPublisher only = new RecordingMetricsPublisher();
    assertSame(only, JSentinelMetricsPublishers.select(List.of(only)));
  }

  @Test
  @DisplayName("select() with multiple providers picks the winner by class name, order-independent")
  void selectMultipleIsDeterministicByClassName() {
    JSentinelMetricsPublisher first = new AlphaPublisher();
    JSentinelMetricsPublisher second = new OmegaPublisher();
    JSentinelMetricsPublisher third = new RecordingMetricsPublisher();
    // Sorted by fully qualified class name: both nested classes
    // (…JSentinelMetricsPublishersTest$…) sort before
    // …RecordingMetricsPublisher ('J' < 'R'), and $AlphaPublisher
    // before $OmegaPublisher — AlphaPublisher is the winner.
    assertSame(first, JSentinelMetricsPublishers.select(List.of(first, second, third)));
    assertSame(first, JSentinelMetricsPublishers.select(List.of(third, second, first)));
    assertSame(first, JSentinelMetricsPublishers.select(List.of(second, first, third)));
  }

  @Test
  @DisplayName("the default increment(String) delegates with delta 1")
  void defaultIncrementDelegatesWithDeltaOne() {
    RecordingMetricsPublisher recording = new RecordingMetricsPublisher();
    recording.increment(JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL);
    recording.increment(JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL);
    recording.increment(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL, 5L);
    recording.gauge(JSentinelMetricNames.SESSION_ACTIVE, 3L);
    recording.gauge(JSentinelMetricNames.SESSION_ACTIVE, 9L);
    assertEquals(2L, recording.counter(JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL));
    assertEquals(5L, recording.counter(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL));
    assertEquals(0L, recording.counter(JSentinelMetricNames.EVENTBUS_DEADLETTER_TOTAL));
    assertEquals(9L, recording.gauge(JSentinelMetricNames.SESSION_ACTIVE));
    assertEquals(Map.of(
            JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL, 2L,
            JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL, 5L),
        recording.counters());
    recording.clear();
    assertEquals(Map.of(), recording.counters());
    assertEquals(Map.of(), recording.gauges());
  }

  @Test
  @DisplayName("utility class is final with a single private constructor")
  void utilityClassIsFinalWithPrivateConstructor() {
    assertTrue(Modifier.isFinal(JSentinelMetricsPublishers.class.getModifiers()));
    Constructor<?>[] constructors =
        JSentinelMetricsPublishers.class.getDeclaredConstructors();
    assertEquals(1, constructors.length);
    assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
  }

  /** Class name sorts first among the three providers in the multi test. */
  static final class AlphaPublisher implements JSentinelMetricsPublisher {
    @Override
    public void increment(String counterName, long delta) {
      // intentionally empty
    }

    @Override
    public void gauge(String gaugeName, long value) {
      // intentionally empty
    }
  }

  /** Class name sorts after {@link AlphaPublisher}. */
  static final class OmegaPublisher implements JSentinelMetricsPublisher {
    @Override
    public void increment(String counterName, long delta) {
      // intentionally empty
    }

    @Override
    public void gauge(String gaugeName, long value) {
      // intentionally empty
    }
  }
}
