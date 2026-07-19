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
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSentinelMetricNamesTest {

  @Test
  @DisplayName("the 9 event-bus names are Konzept-verbatim")
  void eventBusNamesAreConceptVerbatim() {
    assertEquals("security.eventbus.published.total",
        JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL);
    assertEquals("security.eventbus.rejected.total",
        JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL);
    assertEquals("security.eventbus.replay.detected.total",
        JSentinelMetricNames.EVENTBUS_REPLAY_DETECTED_TOTAL);
    assertEquals("security.eventbus.sequence.violation.total",
        JSentinelMetricNames.EVENTBUS_SEQUENCE_VIOLATION_TOTAL);
    assertEquals("security.eventbus.signature.invalid.total",
        JSentinelMetricNames.EVENTBUS_SIGNATURE_INVALID_TOTAL);
    assertEquals("security.eventbus.deadletter.total",
        JSentinelMetricNames.EVENTBUS_DEADLETTER_TOTAL);
    assertEquals("security.eventbus.listener.failure.total",
        JSentinelMetricNames.EVENTBUS_LISTENER_FAILURE_TOTAL);
    assertEquals("security.eventbus.sse.connections.active",
        JSentinelMetricNames.EVENTBUS_SSE_CONNECTIONS_ACTIVE);
    assertEquals("security.eventbus.sse.reconnects.total",
        JSentinelMetricNames.EVENTBUS_SSE_RECONNECTS_TOTAL);
  }

  @Test
  @DisplayName("the minted auth / session / audit names are pinned")
  void mintedNamesArePinned() {
    assertEquals("security.auth.login.success.total",
        JSentinelMetricNames.AUTH_LOGIN_SUCCESS_TOTAL);
    assertEquals("security.auth.login.failure.total",
        JSentinelMetricNames.AUTH_LOGIN_FAILURE_TOTAL);
    assertEquals("security.auth.lockout.total",
        JSentinelMetricNames.AUTH_LOCKOUT_TOTAL);
    assertEquals("security.authz.denied.total",
        JSentinelMetricNames.AUTHZ_DENIED_TOTAL);
    assertEquals("security.session.created.total",
        JSentinelMetricNames.SESSION_CREATED_TOTAL);
    assertEquals("security.session.revoked.total",
        JSentinelMetricNames.SESSION_REVOKED_TOTAL);
    assertEquals("security.session.active",
        JSentinelMetricNames.SESSION_ACTIVE);
    assertEquals("security.audit.store.lag",
        JSentinelMetricNames.AUDIT_STORE_LAG);
  }

  @Test
  @DisplayName("all catalog names are globally unique and security.-prefixed")
  void allNamesAreUniqueAndPrefixed() throws IllegalAccessException {
    List<String> values = new ArrayList<>();
    for (Field field : JSentinelMetricNames.class.getDeclaredFields()) {
      int modifiers = field.getModifiers();
      if (Modifier.isPublic(modifiers)
          && Modifier.isStatic(modifiers)
          && Modifier.isFinal(modifiers)
          && field.getType() == String.class) {
        values.add((String) field.get(null));
      }
    }
    assertEquals(17, values.size(), "expected the full 17-name catalog");
    Set<String> unique = new HashSet<>(values);
    assertEquals(values.size(), unique.size(), "metric names must be globally unique");
    for (String value : values) {
      assertTrue(value.startsWith("security."),
          "metric name must carry the security. prefix: " + value);
    }
  }

  @Test
  @DisplayName("catalog class is final with a single private constructor")
  void catalogClassIsFinalWithPrivateConstructor() {
    assertTrue(Modifier.isFinal(JSentinelMetricNames.class.getModifiers()));
    Constructor<?>[] constructors = JSentinelMetricNames.class.getDeclaredConstructors();
    assertEquals(1, constructors.length);
    assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
    assertFalse(Modifier.isPublic(constructors[0].getModifiers()));
  }
}
