/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ContextAwarePasswordValidatorTest {

  private final ContextAwarePasswordValidator validator =
      new ContextAwarePasswordValidator();
  private final PasswordInputPolicy policy = PasswordInputPolicy.defaults();

  private static PasswordContext aliceContext(Set<String> forbidden) {
    return PasswordContext.fromEmail(
        "alice", "alice@example.com", TenantId.DEFAULT,
        forbidden == null ? Set.of() : forbidden);
  }

  @Test
  @DisplayName("Strong passphrase without context overlap is accepted")
  void acceptStrongPassphrase() {
    PasswordInputValidationResult result = validator.validate(
        SecretValue.ofString("correct horse battery staple 47"),
        policy, aliceContext(Set.of()));
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE, result);
  }

  @Test
  @DisplayName("Password containing the username is rejected with CONTAINS_USERNAME")
  void rejectContainsUsername() {
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("Alice-with-suffix"),
            policy, aliceContext(Set.of())));
    assertEquals(PasswordInputViolation.CONTAINS_USERNAME, r.violation());
  }

  @Test
  @DisplayName("Case-insensitive: 'ALICE' inside the password still rejected")
  void caseInsensitiveUsername() {
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("hunterALICE22"),
            policy, aliceContext(Set.of())));
    assertEquals(PasswordInputViolation.CONTAINS_USERNAME, r.violation());
  }

  @Test
  @DisplayName("Password containing the email local part is rejected")
  void rejectEmailLocalPart() {
    PasswordContext ctx = PasswordContext.fromEmail(
        "ar123", "ada@example.com", TenantId.DEFAULT, Set.of());
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("hunterADA22"), policy, ctx));
    assertEquals(PasswordInputViolation.CONTAINS_EMAIL_LOCAL_PART,
        r.violation());
  }

  @Test
  @DisplayName("Password containing the email domain is rejected")
  void rejectEmailDomain() {
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("hunter-example.com-22"),
            policy, aliceContext(Set.of())));
    assertEquals(PasswordInputViolation.CONTAINS_EMAIL_DOMAIN,
        r.violation());
  }

  @Test
  @DisplayName("Password containing an operator forbidden term is rejected")
  void rejectForbiddenTerm() {
    PasswordContext ctx = aliceContext(Set.of("Acme", "RoadRunner"));
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("hunter-acme-22"), policy, ctx));
    assertEquals(PasswordInputViolation.CONTAINS_FORBIDDEN_TERM, r.violation());
  }

  @Test
  @DisplayName("Structural violation wins over context check (TOO_SHORT before CONTAINS_USERNAME)")
  void structuralWinsOverContext() {
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofString("alice"), policy, aliceContext(Set.of())));
    assertEquals(PasswordInputViolation.TOO_SHORT, r.violation());
  }

  @Test
  @DisplayName("No composition rule by default: long passphrase without symbols accepted")
  void noCompositionRule() {
    PasswordInputValidationResult result = validator.validate(
        SecretValue.ofString("longish lower case passphrase only"),
        policy, aliceContext(Set.of()));
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE, result);
  }

  @Test
  @DisplayName("Max length still applies: 1025 'a' rejected with TOO_LONG")
  void maxLengthStillApplies() {
    char[] tooLong = new char[1025];
    java.util.Arrays.fill(tooLong, 'q');
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(
            SecretValue.ofChars(tooLong), policy, aliceContext(Set.of())));
    assertEquals(PasswordInputViolation.TOO_LONG, r.violation());
  }

  @Test
  @DisplayName("PasswordContext.fromEmail handles missing / blank / malformed emails gracefully")
  void contextFromEmailEdgeCases() {
    PasswordContext none = PasswordContext.fromEmail(
        "alice", null, TenantId.DEFAULT, Set.of());
    org.junit.jupiter.api.Assertions.assertEquals(Optional.empty(), none.emailLocalPart());
    PasswordContext blank = PasswordContext.fromEmail(
        "alice", "  ", TenantId.DEFAULT, Set.of());
    org.junit.jupiter.api.Assertions.assertEquals(Optional.empty(), blank.emailLocalPart());
    PasswordContext bad = PasswordContext.fromEmail(
        "alice", "no-at-sign", TenantId.DEFAULT, Set.of());
    org.junit.jupiter.api.Assertions.assertEquals(Optional.empty(), bad.emailLocalPart());
    PasswordContext ok = PasswordContext.fromEmail(
        "alice", "ada@example.com", TenantId.DEFAULT, Set.of());
    org.junit.jupiter.api.Assertions.assertEquals(Optional.of("ada"), ok.emailLocalPart());
    org.junit.jupiter.api.Assertions.assertEquals(Optional.of("example.com"),
        ok.emailDomain());
  }

  @Test
  @DisplayName("PasswordContext invariants reject blank username and null fields")
  void contextInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordContext(" ",
            Optional.empty(), Optional.empty(), TenantId.DEFAULT, Set.of()));
    assertThrows(NullPointerException.class,
        () -> new PasswordContext("alice",
            null, Optional.empty(), TenantId.DEFAULT, Set.of()));
    assertThrows(NullPointerException.class,
        () -> new PasswordContext("alice",
            Optional.empty(), Optional.empty(), null, Set.of()));
  }

  @Test
  @DisplayName("Forbidden term set is unmodifiable after construction")
  void forbiddenTermsImmutable() {
    PasswordContext ctx = aliceContext(Set.of("Acme"));
    assertThrows(UnsupportedOperationException.class,
        () -> ctx.forbiddenTerms().add("RoadRunner"));
  }
}
