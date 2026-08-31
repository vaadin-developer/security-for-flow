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
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyBuilderTest {

  private static PolicyContext ctx() {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", "read", Map.of()),
        "test.policy");
  }

  @Test
  @DisplayName("Policy.named rejects blank name")
  void rejectsBlankName() {
    assertThrows(IllegalArgumentException.class, () -> Policy.named(""));
    assertThrows(IllegalArgumentException.class, () -> Policy.named("   "));
  }

  @Test
  @DisplayName("Policy.named rejects null name")
  void rejectsNullName() {
    assertThrows(IllegalArgumentException.class, () -> Policy.named(null));
  }

  @Test
  @DisplayName("build() without any predicate throws IllegalStateException")
  void buildWithoutPredicates() {
    assertThrows(IllegalStateException.class, () -> Policy.named("p").build());
  }

  @Test
  @DisplayName("allowIf/orIf rejects null predicate")
  void allowIfRejectsNull() {
    PolicyBuilder b = Policy.named("p");
    assertThrows(NullPointerException.class, () -> b.allowIf(null));
    assertThrows(NullPointerException.class, () -> b.orIf(null));
  }

  @Test
  @DisplayName("denyIf rejects null predicate")
  void denyIfRejectsNull() {
    PolicyBuilder b = Policy.named("p");
    assertThrows(NullPointerException.class, () -> b.denyIf(null));
  }

  @Test
  @DisplayName("deny(reason) rejects blank reason")
  void denyRejectsBlankReason() {
    PolicyBuilder b = Policy.named("p");
    assertThrows(IllegalArgumentException.class, () -> b.deny(""));
    assertThrows(IllegalArgumentException.class, () -> b.deny("  "));
    assertThrows(IllegalArgumentException.class, () -> b.deny(null));
  }

  @Test
  @DisplayName("allow-only policy yields Allowed when predicate matches")
  void allowOnlyMatches() {
    Policy p = Policy.named("p").allowIf(c -> true).build();
    assertInstanceOf(PolicyDecision.Allowed.class, p.evaluate(ctx()));
  }

  @Test
  @DisplayName("allow-only policy yields fall-through Denied when no predicate matches")
  void allowOnlyFallThrough() {
    Policy p = Policy.named("p")
        .allowIf(c -> false)
        .deny("must satisfy the allow rule")
        .build();
    PolicyDecision.Denied denied =
        assertInstanceOf(PolicyDecision.Denied.class, p.evaluate(ctx()));
    assertEquals("must satisfy the allow rule", denied.reason());
  }

  @Test
  @DisplayName("orIf is an alias of allowIf: any matching allow-predicate grants")
  void orIfAlias() {
    Policy p = Policy.named("p")
        .allowIf(c -> false)
        .orIf(c -> true)
        .build();
    assertInstanceOf(PolicyDecision.Allowed.class, p.evaluate(ctx()));
  }

  @Test
  @DisplayName("denyIf takes precedence over allowIf")
  void denyTakesPrecedence() {
    Policy p = Policy.named("p")
        .allowIf(c -> true)
        .denyIf(c -> true)
        .build();
    PolicyDecision.Denied denied =
        assertInstanceOf(PolicyDecision.Denied.class, p.evaluate(ctx()));
    assertEquals("policy 'p' explicit-deny", denied.reason());
  }

  @Test
  @DisplayName("non-matching denyIf falls through to allow path")
  void denyIfNoMatchAllowsThrough() {
    Policy p = Policy.named("p")
        .denyIf(c -> false)
        .allowIf(c -> true)
        .build();
    assertInstanceOf(PolicyDecision.Allowed.class, p.evaluate(ctx()));
  }

  @Test
  @DisplayName("default deny reason falls back to generic when deny(...) is not called")
  void defaultDenyReasonGeneric() {
    Policy p = Policy.named("p").allowIf(c -> false).build();
    PolicyDecision.Denied denied =
        assertInstanceOf(PolicyDecision.Denied.class, p.evaluate(ctx()));
    assertEquals(PolicyBuilder.GENERIC_DEFAULT_DENY_REASON, denied.reason());
  }

  @Test
  @DisplayName("Policy.name returns the configured name")
  void nameReturnsConfigured() {
    Policy p = Policy.named("my.policy").allowIf(c -> true).build();
    assertEquals("my.policy", p.name());
  }

  @Test
  @DisplayName("Policy.evaluate rejects null context")
  void evaluateRejectsNullContext() {
    Policy p = Policy.named("p").allowIf(c -> true).build();
    assertThrows(NullPointerException.class, () -> p.evaluate(null));
  }
}
