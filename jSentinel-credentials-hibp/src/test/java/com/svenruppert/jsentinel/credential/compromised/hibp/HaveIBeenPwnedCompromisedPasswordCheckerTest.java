/*-
 * #%L
 * Security Credentials — HIBP (HaveIBeenPwned) Opt-In
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
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
package com.svenruppert.jsentinel.credential.compromised.hibp;

import com.svenruppert.jsentinel.credential.compromised.CompromisedPasswordResult;
import com.svenruppert.jsentinel.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HaveIBeenPwnedCompromisedPasswordCheckerTest {

  /** Records every prefix passed to the range lookup. */
  private static final class CapturingLookup implements
      Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> {
    final List<String> prefixes = new ArrayList<>();
    final Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> delegate;

    CapturingLookup(
        Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> delegate) {
      this.delegate = delegate;
    }

    @Override
    public HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse apply(String prefix) {
      prefixes.add(prefix);
      return delegate.apply(prefix);
    }
  }

  private static String sha1HexUpper(String s) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-1").digest(s.getBytes("UTF-8"));
      StringBuilder sb = new StringBuilder();
      for (byte b : d) {
        sb.append(String.format("%02X", b));
      }
      return sb.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  @DisplayName("Only the first five SHA-1 hex chars are sent — no plaintext leaves the JVM")
  void onlyPrefixIsTransmitted() {
    CapturingLookup lookup = new CapturingLookup(
        prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            "", null));
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(lookup);
    checker.check(SecretValue.ofString("hunter222"));
    assertEquals(1, lookup.prefixes.size());
    String prefix = lookup.prefixes.get(0);
    assertEquals(5, prefix.length(),
        "the prefix must be exactly 5 hex characters");
    assertTrue(prefix.matches("[0-9A-F]{5}"),
        "the prefix must be uppercase hex");
    // verify it really matches the candidate's SHA-1 prefix
    String expected = sha1HexUpper("hunter222").substring(0, 5);
    assertEquals(expected, prefix);
    // verify nothing in the captured prefix list reveals the plaintext
    for (String p : lookup.prefixes) {
      assertTrue(!p.toLowerCase(Locale.ROOT).contains("hunter"),
          "prefix must not contain plaintext");
    }
  }

  @Test
  @DisplayName("Suffix match in response body produces Pwned with reported count")
  void suffixMatchProducesPwned() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5);
    String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\n"
        + suffix + ":42\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:9\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("hunter222"));
    CompromisedPasswordResult.Pwned p = assertInstanceOf(
        CompromisedPasswordResult.Pwned.class, r);
    assertEquals(42L, p.occurrences());
  }

  @Test
  @DisplayName("No suffix match yields Clean")
  void noSuffixMatchClean() {
    String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\n"
        + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:9\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("an-unguessable-passphrase")));
  }

  @Test
  @DisplayName("Empty response body yields Clean (no entries in the range)")
  void emptyBodyClean() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                "", null));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("hunter222")));
  }

  @Test
  @DisplayName("Suffix match is case-insensitive (server may respond in lower or mixed case)")
  void suffixMatchCaseInsensitive() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5).toLowerCase(Locale.ROOT);
    String body = suffix + ":3\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("hunter222"));
    assertInstanceOf(CompromisedPasswordResult.Pwned.class, r);
  }

  @Test
  @DisplayName("Range lookup reporting NETWORK propagates to CheckFailed.NETWORK")
  void networkFailurePropagates() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                null, CompromisedPasswordResult.FailureReason.NETWORK));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("anything"));
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class, r);
    assertEquals(CompromisedPasswordResult.FailureReason.NETWORK, cf.reason());
  }

  @Test
  @DisplayName("Range lookup reporting RATE_LIMITED propagates")
  void rateLimitedPropagates() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                null, CompromisedPasswordResult.FailureReason.RATE_LIMITED));
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class,
        checker.check(SecretValue.ofString("anything")));
    assertEquals(CompromisedPasswordResult.FailureReason.RATE_LIMITED,
        cf.reason());
  }

  @Test
  @DisplayName("Unexpected RuntimeException from the lookup degrades to CheckFailed.UNKNOWN")
  void unexpectedExceptionDegrades() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> {
              throw new RuntimeException("boom");
            });
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class,
        checker.check(SecretValue.ofString("anything")));
    assertEquals(CompromisedPasswordResult.FailureReason.UNKNOWN, cf.reason());
  }

  @Test
  @DisplayName("RangeResponse invariant: exactly one of body / failure is non-null")
  void rangeResponseInvariant() {
    assertThrows(IllegalArgumentException.class,
        () -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            "x", CompromisedPasswordResult.FailureReason.NETWORK));
  }

  @Test
  @DisplayName("usingJdkHttpClient factory rejects null endpoint and timeout")
  void factoryInvariants() {
    assertThrows(NullPointerException.class,
        () -> HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            null, java.time.Duration.ofSeconds(2)));
    assertThrows(NullPointerException.class,
        () -> HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            HaveIBeenPwnedCompromisedPasswordChecker.DEFAULT_ENDPOINT, null));
  }

  @Test
  @DisplayName("Response with CR-LF line endings is handled")
  void crlfLineEndings() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5);
    String body = suffix + ":11\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult.Pwned p = assertInstanceOf(
        CompromisedPasswordResult.Pwned.class,
        checker.check(SecretValue.ofString("hunter222")));
    assertEquals(11L, p.occurrences());
  }
}
