package eu.jsentinel.jcustos.monitoring.metrics;

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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NoOpJSentinelMetricsPublisherTest {

  @Test
  @DisplayName("INSTANCE is a singleton with no public constructor")
  void instanceIsSingleton() {
    assertSame(NoOpJSentinelMetricsPublisher.INSTANCE,
        NoOpJSentinelMetricsPublisher.INSTANCE);
    assertTrue(Modifier.isFinal(NoOpJSentinelMetricsPublisher.class.getModifiers()));
    Constructor<?>[] constructors =
        NoOpJSentinelMetricsPublisher.class.getDeclaredConstructors();
    assertEquals(1, constructors.length);
    assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
  }

  /**
   * The no-op tolerates literally any input, including {@code null}
   * names — it must not even NPE. Note: this liberal null tolerance
   * is a no-op-only property; the {@link JSentinelMetricsPublisher}
   * contract itself requires non-null metric names.
   */
  @Test
  @DisplayName("all methods tolerate any input, null names included")
  void allMethodsTolerateAnyInput() {
    NoOpJSentinelMetricsPublisher noOp = NoOpJSentinelMetricsPublisher.INSTANCE;
    assertDoesNotThrow(() -> noOp.increment(JSentinelMetricNames.AUTH_LOGIN_SUCCESS_TOTAL));
    assertDoesNotThrow(() -> noOp.increment(JSentinelMetricNames.AUTHZ_DENIED_TOTAL, 42L));
    assertDoesNotThrow(() -> noOp.increment(null));
    assertDoesNotThrow(() -> noOp.increment(null, Long.MIN_VALUE));
    assertDoesNotThrow(() -> noOp.increment("", -1L));
    assertDoesNotThrow(() -> noOp.gauge(JSentinelMetricNames.SESSION_ACTIVE, 7L));
    assertDoesNotThrow(() -> noOp.gauge(null, Long.MAX_VALUE));
    assertDoesNotThrow(() -> noOp.gauge("", 0L));
  }
}
