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
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CompromisedPasswordCoreTest {

  @Test
  @DisplayName("NoOp checker returns Clean for any input")
  void noOpAlwaysClean() {
    CompromisedPasswordChecker noOp = NoOpCompromisedPasswordChecker.INSTANCE;
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        noOp.check(SecretValue.ofString("hunter222")));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        noOp.check(SecretValue.ofString("Password123!")));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        noOp.check(SecretValue.ofString("")));
  }

  @Test
  @DisplayName("LocalBlocklist matches exact entry case-insensitively")
  void blocklistCaseInsensitiveMatch() {
    LocalBlocklistCompromisedPasswordChecker checker =
        new LocalBlocklistCompromisedPasswordChecker(
            List.of("password", "123456", "letmein"));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("PASSWORD"));
    CompromisedPasswordResult.Pwned p = assertInstanceOf(
        CompromisedPasswordResult.Pwned.class, r);
    assertEquals(1L, p.occurrences());
  }

  @Test
  @DisplayName("LocalBlocklist returns Clean for non-listed entry")
  void blocklistMiss() {
    LocalBlocklistCompromisedPasswordChecker checker =
        new LocalBlocklistCompromisedPasswordChecker(
            List.of("password", "123456"));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("correct horse battery staple")));
  }

  @Test
  @DisplayName("LocalBlocklist normalises entries: trim + lowercase + drop blanks")
  void blocklistNormalises() {
    LocalBlocklistCompromisedPasswordChecker checker =
        new LocalBlocklistCompromisedPasswordChecker(
            List.of("  PASSWORD  ", "", " ", "Letmein"));
    assertEquals(2, checker.size(),
        "blank entries must be dropped; case must collapse");
    assertInstanceOf(CompromisedPasswordResult.Pwned.class,
        checker.check(SecretValue.ofString("password")));
    assertInstanceOf(CompromisedPasswordResult.Pwned.class,
        checker.check(SecretValue.ofString("letmein")));
  }

  @Test
  @DisplayName("CompromisedPasswordPolicy.defaults: set/change only, ALLOW on failure")
  void policyDefaults() {
    CompromisedPasswordPolicy d = CompromisedPasswordPolicy.defaults();
    assertEquals(true, d.checkOnSetOrChange());
    assertEquals(false, d.checkOnLogin());
    assertEquals(CheckFailurePolicy.ALLOW, d.onFailure());
  }

  @Test
  @DisplayName("CompromisedPasswordPolicy.failClosed maps failure → BLOCK")
  void policyFailClosed() {
    assertEquals(CheckFailurePolicy.BLOCK,
        CompromisedPasswordPolicy.failClosed().onFailure());
  }

  @Test
  @DisplayName("CompromisedPasswordPolicy.disabled disables set/change checking")
  void policyDisabled() {
    assertEquals(false,
        CompromisedPasswordPolicy.disabled().checkOnSetOrChange());
  }

  @Test
  @DisplayName("CheckFailed requires non-null reason")
  void checkFailedReasonRequired() {
    assertThrows(NullPointerException.class,
        () -> new CompromisedPasswordResult.CheckFailed(null));
  }

  @Test
  @DisplayName("Pwned invariant: occurrences must be >= 1")
  void pwnedInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new CompromisedPasswordResult.Pwned(0L));
    assertThrows(IllegalArgumentException.class,
        () -> new CompromisedPasswordResult.Pwned(-5L));
  }

  @Test
  @DisplayName("LocalBlocklist tolerates a null entry in the source collection")
  void blocklistDropsNullEntries() {
    LocalBlocklistCompromisedPasswordChecker checker =
        new LocalBlocklistCompromisedPasswordChecker(
            java.util.Arrays.asList("ok", null, "letmein"));
    assertEquals(2, checker.size());
  }

  @Test
  @DisplayName("LocalBlocklist with empty source yields zero entries")
  void blocklistEmpty() {
    LocalBlocklistCompromisedPasswordChecker checker =
        new LocalBlocklistCompromisedPasswordChecker(Set.of());
    assertEquals(0, checker.size());
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("anything")));
  }
}
