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

import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.impl.InMemoryResourceResolverRegistry;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourcePredicatesTest {

  private InMemoryResourceResolverRegistry registry;

  @BeforeEach
  void setUp() {
    SecurityServiceResolver.resetAll();
    registry = new InMemoryResourceResolverRegistry();
    SecurityServiceResolver.setResourceResolverRegistry(registry);
  }

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  // ── ownerMatchesSubject ───────────────────────────────────────

  @Test
  @DisplayName("ownerMatchesSubject matches when owner attribute equals subject id")
  void ownerMatchesSubjectHit() {
    registry.register(documentResolverWith("42", "u-alice"));
    PolicyContext ctx = ctx(subjectWithId("u-alice"), new ResourceRef("document", "42"));
    assertTrue(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when owner differs")
  void ownerMatchesSubjectMiss() {
    registry.register(documentResolverWith("42", "u-alice"));
    PolicyContext ctx = ctx(subjectWithId("u-bob"), new ResourceRef("document", "42"));
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when subject is absent")
  void ownerMatchesSubjectAnonymous() {
    registry.register(documentResolverWith("42", "u-alice"));
    PolicyContext ctx = ctx(null, new ResourceRef("document", "42"));
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when resourceRef is absent")
  void ownerMatchesSubjectNoResourceRef() {
    PolicyContext ctx = ctx(subjectWithId("u-alice"), null);
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when resourceRef has wrong type")
  void ownerMatchesSubjectTypeMismatch() {
    registry.register(documentResolverWith("42", "u-alice"));
    PolicyContext ctx = ctx(subjectWithId("u-alice"), new ResourceRef("user", "42"));
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when no resolver is registered")
  void ownerMatchesSubjectNoResolver() {
    PolicyContext ctx = ctx(subjectWithId("u-alice"), new ResourceRef("document", "42"));
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject does not match when resolver cannot resolve the id")
  void ownerMatchesSubjectUnknownId() {
    registry.register(documentResolverWith("99", "u-alice"));
    PolicyContext ctx = ctx(subjectWithId("u-alice"), new ResourceRef("document", "42"));
    assertFalse(ResourcePredicates.ownerMatchesSubject("document", "ownerId").test(ctx));
  }

  @Test
  @DisplayName("ownerMatchesSubject rejects blank arguments")
  void ownerMatchesSubjectRejectsBlanks() {
    assertThrows(IllegalArgumentException.class,
        () -> ResourcePredicates.ownerMatchesSubject("", "ownerId"));
    assertThrows(IllegalArgumentException.class,
        () -> ResourcePredicates.ownerMatchesSubject("document", ""));
    assertThrows(NullPointerException.class,
        () -> ResourcePredicates.ownerMatchesSubject(null, "ownerId"));
    assertThrows(NullPointerException.class,
        () -> ResourcePredicates.ownerMatchesSubject("document", null));
  }

  // ── resourceAttributeEquals ───────────────────────────────────

  @Test
  @DisplayName("resourceAttributeEquals matches present attribute with equal value")
  void resourceAttributeEqualsHit() {
    registry.register(documentResolverWith("42", "u-alice", "status", "published"));
    PolicyContext ctx = ctx(null, new ResourceRef("document", "42"));
    assertTrue(ResourcePredicates.resourceAttributeEquals("document", "status", "published")
        .test(ctx));
  }

  @Test
  @DisplayName("resourceAttributeEquals does not match when value differs")
  void resourceAttributeEqualsMiss() {
    registry.register(documentResolverWith("42", "u-alice", "status", "draft"));
    PolicyContext ctx = ctx(null, new ResourceRef("document", "42"));
    assertFalse(ResourcePredicates.resourceAttributeEquals("document", "status", "published")
        .test(ctx));
  }

  @Test
  @DisplayName("resourceAttributeEquals does not match when type differs")
  void resourceAttributeEqualsTypeMismatch() {
    registry.register(documentResolverWith("42", "u-alice", "status", "published"));
    PolicyContext ctx = ctx(null, new ResourceRef("user", "42"));
    assertFalse(ResourcePredicates.resourceAttributeEquals("document", "status", "published")
        .test(ctx));
  }

  @Test
  @DisplayName("resourceAttributeEquals matches null expected against missing attribute")
  void resourceAttributeEqualsNullExpected() {
    registry.register(documentResolverWith("42", "u-alice")); // no status attribute
    PolicyContext ctx = ctx(null, new ResourceRef("document", "42"));
    assertTrue(ResourcePredicates.resourceAttributeEquals("document", "status", null)
        .test(ctx));
  }

  @Test
  @DisplayName("resourceAttributeEquals rejects blank arguments")
  void resourceAttributeEqualsRejectsBlanks() {
    assertThrows(IllegalArgumentException.class,
        () -> ResourcePredicates.resourceAttributeEquals("", "status", "x"));
    assertThrows(IllegalArgumentException.class,
        () -> ResourcePredicates.resourceAttributeEquals("document", "", "x"));
  }

  // ── hasResource ───────────────────────────────────────────────

  @Test
  @DisplayName("hasResource matches when resourceRef of the type is present")
  void hasResourceHit() {
    PolicyContext ctx = ctx(null, new ResourceRef("document", "42"));
    assertTrue(ResourcePredicates.hasResource("document").test(ctx));
  }

  @Test
  @DisplayName("hasResource does not match when resourceRef is absent")
  void hasResourceMissing() {
    PolicyContext ctx = ctx(null, null);
    assertFalse(ResourcePredicates.hasResource("document").test(ctx));
  }

  @Test
  @DisplayName("hasResource does not match when resourceRef has a different type")
  void hasResourceTypeMismatch() {
    PolicyContext ctx = ctx(null, new ResourceRef("user", "42"));
    assertFalse(ResourcePredicates.hasResource("document").test(ctx));
  }

  @Test
  @DisplayName("hasResource rejects blank resource type")
  void hasResourceRejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> ResourcePredicates.hasResource(""));
    assertThrows(NullPointerException.class,
        () -> ResourcePredicates.hasResource(null));
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static PolicyContext ctx(SecuritySubject subject, ResourceRef ref) {
    AccessContext accessContext = new AccessContext(
        subject == null ? Optional.empty() : Optional.of(subject),
        "rest-endpoint", "/x", "read", Map.of());
    return new PolicyContext(accessContext, "test.policy", ref);
  }

  private static SecuritySubject subjectWithId(String id) {
    return new SecuritySubject(id, id, Set.of(), Set.of());
  }

  private static ResourceResolver<Map<String, Object>> documentResolverWith(
      String id, String ownerId, String... extra) {
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("ownerId", ownerId);
    for (int i = 0; i + 1 < extra.length; i += 2) {
      attributes.put(extra[i], extra[i + 1]);
    }
    Map<String, Object> immutable = Map.copyOf(attributes);
    return new ResourceResolver<>() {
      @Override
      public String resourceType() {
        return "document";
      }

      @Override
      public Optional<Map<String, Object>> resolve(String requestedId) {
        return id.equals(requestedId) ? Optional.of(immutable) : Optional.empty();
      }

      @Override
      public Map<String, Object> attributes(Map<String, Object> resource) {
        return resource;
      }
    };
  }
}
