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
package com.svenruppert.jsentinel.policy.api;

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyContextTest {

  private static AccessContext accessContext() {
    return new AccessContext(
        Optional.empty(),
        "rest-endpoint",
        "/documents",
        "read",
        Map.of());
  }

  private static AccessContext accessContextWithSubject(JSentinelSubject subject) {
    return new AccessContext(
        Optional.of(subject),
        "rest-endpoint",
        "/documents",
        "read",
        Map.of());
  }

  @Test
  @DisplayName("constructor rejects null accessContext")
  void rejectsNullAccessContext() {
    assertThrows(NullPointerException.class,
        () -> new PolicyContext(null, "policy.x"));
  }

  @Test
  @DisplayName("constructor rejects null policyName")
  void rejectsNullPolicyName() {
    assertThrows(IllegalArgumentException.class,
        () -> new PolicyContext(accessContext(), null));
  }

  @Test
  @DisplayName("constructor rejects blank policyName")
  void rejectsBlankPolicyName() {
    assertThrows(IllegalArgumentException.class,
        () -> new PolicyContext(accessContext(), "   "));
  }

  @Test
  @DisplayName("constructor rejects null resourceAttributes")
  void rejectsNullAttributes() {
    assertThrows(NullPointerException.class,
        () -> new PolicyContext(accessContext(), "policy.x", (Map<String, Object>) null));
  }

  @Test
  @DisplayName("convenience constructor defaults resourceAttributes to empty map")
  void convenienceConstructorDefaultsAttributes() {
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x");
    assertTrue(ctx.resourceAttributes().isEmpty());
  }

  @Test
  @DisplayName("resourceAttributes is defensively copied")
  void resourceAttributesDefensivelyCopied() {
    Map<String, Object> mutable = new HashMap<>();
    mutable.put("ownerId", "u-1");
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x", mutable);
    mutable.put("ownerId", "u-2");
    assertEquals("u-1", ctx.resourceAttributes().get("ownerId"));
  }

  @Test
  @DisplayName("subject() returns the wrapped access context's subject")
  void subjectShortcut() {
    JSentinelSubject subject = new JSentinelSubject("u-1", "u-1", Set.of(), Set.of());
    PolicyContext ctx = new PolicyContext(accessContextWithSubject(subject), "policy.x");
    assertTrue(ctx.subject().isPresent());
    assertSame(subject, ctx.subject().orElseThrow());
  }

  @Test
  @DisplayName("subject() returns empty Optional when no subject is bound")
  void subjectAbsent() {
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x");
    assertTrue(ctx.subject().isEmpty());
  }

  @Test
  @DisplayName("two-arg + three-arg ctors default resourceRef to empty Optional")
  void twoAndThreeArgCtorsHaveEmptyResourceRef() {
    PolicyContext two = new PolicyContext(accessContext(), "policy.x");
    PolicyContext three = new PolicyContext(accessContext(), "policy.x", Map.of("k", "v"));
    assertTrue(two.resourceRef().isEmpty());
    assertTrue(three.resourceRef().isEmpty());
  }

  @Test
  @DisplayName("three-arg ResourceRef ctor exposes the reference and empty attributes")
  void threeArgResourceRefCtor() {
    ResourceRef ref = new ResourceRef("document", "42");
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x", ref);
    assertTrue(ctx.resourceRef().isPresent());
    assertSame(ref, ctx.resourceRef().orElseThrow());
    assertTrue(ctx.resourceAttributes().isEmpty());
  }

  @Test
  @DisplayName("three-arg ResourceRef ctor accepts null and maps to empty Optional")
  void threeArgResourceRefCtorAcceptsNull() {
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x", (ResourceRef) null);
    assertTrue(ctx.resourceRef().isEmpty());
  }

  @Test
  @DisplayName("canonical ctor normalises null resourceRef to empty Optional")
  void canonicalCtorNullResourceRefNormalised() {
    PolicyContext ctx = new PolicyContext(accessContext(), "policy.x", null, Map.of());
    assertTrue(ctx.resourceRef().isEmpty());
  }

  @Test
  @DisplayName("canonical ctor preserves a present resourceRef")
  void canonicalCtorKeepsPresentResourceRef() {
    ResourceRef ref = new ResourceRef("document", "42");
    PolicyContext ctx = new PolicyContext(
        accessContext(), "policy.x", Optional.of(ref), Map.of());
    assertSame(ref, ctx.resourceRef().orElseThrow());
  }
}
