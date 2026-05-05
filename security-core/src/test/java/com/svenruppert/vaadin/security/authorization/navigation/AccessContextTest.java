/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.authorization.navigation;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AccessContext")
class AccessContextTest {

  @Test
  @DisplayName("stores neutral access metadata")
  void storesNeutralMetadata() {
    SecuritySubject subject = new SecuritySubject("u1", "User", Set.of(), Set.of());

    AccessContext context = new AccessContext(
        Optional.of(subject),
        "rest-endpoint",
        "/api/documents/{id}",
        "delete",
        Map.of("method", "DELETE"));

    assertEquals(Optional.of(subject), context.subject());
    assertEquals("rest-endpoint", context.resourceType());
    assertEquals("/api/documents/{id}", context.resourceName());
    assertEquals("delete", context.operation());
    assertEquals("DELETE", context.attributes().get("method"));
  }

  @Test
  @DisplayName("attributes are defensively copied")
  void attributesAreDefensivelyCopied() {
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("method", "GET");

    AccessContext context = new AccessContext(
        Optional.empty(), "rest-endpoint", "/api", "read", attributes);
    attributes.put("method", "POST");

    assertEquals("GET", context.attributes().get("method"));
    assertThrows(UnsupportedOperationException.class,
        () -> context.attributes().put("x", "y"));
  }

  @Test
  @DisplayName("compatibility constructor exposes path and target")
  void compatibilityConstructor() {
    AccessContext context = new AccessContext("admin", AccessContextTest.class, Map.of());

    assertEquals("vaadin-view", context.resourceType());
    assertEquals("navigate", context.operation());
    assertEquals("admin", context.path());
    assertEquals(AccessContextTest.class, context.target());
  }

  @Test
  @DisplayName("compatibility constructor accepts the empty Vaadin root path")
  void compatibilityConstructorAcceptsRootPath() {
    AccessContext context = new AccessContext("", AccessContextTest.class, Map.of());

    assertEquals("", context.path());
    assertEquals(AccessContextTest.class, context.target());
  }
}
