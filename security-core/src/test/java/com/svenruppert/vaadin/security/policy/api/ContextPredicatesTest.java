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
package com.svenruppert.vaadin.security.policy.api;

import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContextPredicatesTest {

  private static PolicyContext ctxWithOperation(String operation) {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", operation, Map.of()),
        "test.policy");
  }

  private static PolicyContext ctxWithResourceType(String resourceType) {
    return new PolicyContext(
        new AccessContext(Optional.empty(), resourceType, "/x", "read", Map.of()),
        "test.policy");
  }

  private static PolicyContext ctxWithAttributes(Map<String, Object> attributes) {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", "read", attributes),
        "test.policy");
  }

  private static PolicyContext ctxWithResourceAttributes(Map<String, Object> resourceAttributes) {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", "read", Map.of()),
        "test.policy",
        resourceAttributes);
  }

  @Test
  @DisplayName("operationEquals matches when operation matches exactly")
  void operationEqualsMatches() {
    assertTrue(ContextPredicates.operationEquals("read").test(ctxWithOperation("read")));
  }

  @Test
  @DisplayName("operationEquals does not match for a different operation")
  void operationEqualsDoesNotMatch() {
    assertFalse(ContextPredicates.operationEquals("write").test(ctxWithOperation("read")));
  }

  @Test
  @DisplayName("operationEquals rejects blank operation")
  void operationEqualsRejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> ContextPredicates.operationEquals(""));
    assertThrows(IllegalArgumentException.class,
        () -> ContextPredicates.operationEquals(null));
  }

  @Test
  @DisplayName("resourceTypeEquals matches when resourceType matches exactly")
  void resourceTypeEqualsMatches() {
    assertTrue(ContextPredicates.resourceTypeEquals("rest-endpoint")
        .test(ctxWithResourceType("rest-endpoint")));
  }

  @Test
  @DisplayName("resourceTypeEquals does not match for a different resourceType")
  void resourceTypeEqualsDoesNotMatch() {
    assertFalse(ContextPredicates.resourceTypeEquals("vaadin-view")
        .test(ctxWithResourceType("rest-endpoint")));
  }

  @Test
  @DisplayName("resourceTypeEquals rejects blank resourceType")
  void resourceTypeEqualsRejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> ContextPredicates.resourceTypeEquals(""));
    assertThrows(IllegalArgumentException.class,
        () -> ContextPredicates.resourceTypeEquals(null));
  }

  @Test
  @DisplayName("attributeEquals matches present key with equal value")
  void attributeEqualsMatches() {
    assertTrue(ContextPredicates.attributeEquals("source", "cli")
        .test(ctxWithAttributes(Map.of("source", "cli"))));
  }

  @Test
  @DisplayName("attributeEquals does not match when value differs")
  void attributeEqualsValueDiffers() {
    assertFalse(ContextPredicates.attributeEquals("source", "cli")
        .test(ctxWithAttributes(Map.of("source", "ui"))));
  }

  @Test
  @DisplayName("attributeEquals does not match when key is missing")
  void attributeEqualsKeyMissing() {
    assertFalse(ContextPredicates.attributeEquals("source", "cli")
        .test(ctxWithAttributes(Map.of())));
  }

  @Test
  @DisplayName("attributeEquals rejects blank key")
  void attributeEqualsRejectsBlankKey() {
    assertThrows(IllegalArgumentException.class,
        () -> ContextPredicates.attributeEquals("", "v"));
    assertThrows(NullPointerException.class,
        () -> ContextPredicates.attributeEquals(null, "v"));
  }

  @Test
  @DisplayName("resourceAttributeEquals matches present key with equal value")
  void resourceAttributeEqualsMatches() {
    assertTrue(ContextPredicates.resourceAttributeEquals("ownerId", "u-1")
        .test(ctxWithResourceAttributes(Map.of("ownerId", "u-1"))));
  }

  @Test
  @DisplayName("resourceAttributeEquals does not match when key is missing")
  void resourceAttributeEqualsKeyMissing() {
    assertFalse(ContextPredicates.resourceAttributeEquals("ownerId", "u-1")
        .test(ctxWithResourceAttributes(Map.of())));
  }

  @Test
  @DisplayName("resourceAttributeEquals matches null value when value is absent and expected is null")
  void resourceAttributeEqualsNullValue() {
    assertTrue(ContextPredicates.resourceAttributeEquals("ownerId", null)
        .test(ctxWithResourceAttributes(Map.of())));
  }
}
