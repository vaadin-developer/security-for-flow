package eu.jsentinel.jcustos.monitoring.metrics;

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

class JCustosMetricNamesTest {

  @Test
  @DisplayName("the 9 event-bus names are Konzept-verbatim")
  void eventBusNamesAreConceptVerbatim() {
    assertEquals("security.eventbus.published.total",
        JCustosMetricNames.EVENTBUS_PUBLISHED_TOTAL);
    assertEquals("security.eventbus.rejected.total",
        JCustosMetricNames.EVENTBUS_REJECTED_TOTAL);
    assertEquals("security.eventbus.replay.detected.total",
        JCustosMetricNames.EVENTBUS_REPLAY_DETECTED_TOTAL);
    assertEquals("security.eventbus.sequence.violation.total",
        JCustosMetricNames.EVENTBUS_SEQUENCE_VIOLATION_TOTAL);
    assertEquals("security.eventbus.signature.invalid.total",
        JCustosMetricNames.EVENTBUS_SIGNATURE_INVALID_TOTAL);
    assertEquals("security.eventbus.deadletter.total",
        JCustosMetricNames.EVENTBUS_DEADLETTER_TOTAL);
    assertEquals("security.eventbus.listener.failure.total",
        JCustosMetricNames.EVENTBUS_LISTENER_FAILURE_TOTAL);
    assertEquals("security.eventbus.sse.connections.active",
        JCustosMetricNames.EVENTBUS_SSE_CONNECTIONS_ACTIVE);
    assertEquals("security.eventbus.sse.reconnects.total",
        JCustosMetricNames.EVENTBUS_SSE_RECONNECTS_TOTAL);
  }

  @Test
  @DisplayName("the minted auth / session / audit names are pinned")
  void mintedNamesArePinned() {
    assertEquals("security.auth.login.success.total",
        JCustosMetricNames.AUTH_LOGIN_SUCCESS_TOTAL);
    assertEquals("security.auth.login.failure.total",
        JCustosMetricNames.AUTH_LOGIN_FAILURE_TOTAL);
    assertEquals("security.auth.lockout.total",
        JCustosMetricNames.AUTH_LOCKOUT_TOTAL);
    assertEquals("security.authz.denied.total",
        JCustosMetricNames.AUTHZ_DENIED_TOTAL);
    assertEquals("security.session.created.total",
        JCustosMetricNames.SESSION_CREATED_TOTAL);
    assertEquals("security.session.revoked.total",
        JCustosMetricNames.SESSION_REVOKED_TOTAL);
    assertEquals("security.session.active",
        JCustosMetricNames.SESSION_ACTIVE);
    assertEquals("security.audit.store.lag",
        JCustosMetricNames.AUDIT_STORE_LAG);
  }

  @Test
  @DisplayName("all catalog names are globally unique and security.-prefixed")
  void allNamesAreUniqueAndPrefixed() throws IllegalAccessException {
    List<String> values = new ArrayList<>();
    for (Field field : JCustosMetricNames.class.getDeclaredFields()) {
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
    assertTrue(Modifier.isFinal(JCustosMetricNames.class.getModifiers()));
    Constructor<?>[] constructors = JCustosMetricNames.class.getDeclaredConstructors();
    assertEquals(1, constructors.length);
    assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
    assertFalse(Modifier.isPublic(constructors[0].getModifiers()));
  }
}
