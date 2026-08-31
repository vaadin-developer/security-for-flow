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
package eu.jsentinel.jcustos.bootstrap;

import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.RehashDecision;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase-4 / Prompt 017 — verifies that
 * {@link InitialAdminBootstrapService} preserves the underlying
 * {@link Throwable} in its
 * {@link InitialAdminCreationResult.InternalError} result and writes a
 * WARN-level log entry with stacktrace for both catch sites
 * (hashing failure and persistence failure).
 *
 * @since 00.74.10
 */
@DisplayName("InitialAdminBootstrapService — cause propagation (V00.74.10 / L2)")
class InitialAdminBootstrapServiceCauseTest {

  private static final String OK_PASSWORD = "correct horse battery staple";

  private PrintStream originalErr;
  private ByteArrayOutputStream stderrCapture;

  @BeforeEach
  void redirectStderr() {
    originalErr = System.err;
    stderrCapture = new ByteArrayOutputStream();
    System.setErr(new PrintStream(stderrCapture, true, StandardCharsets.UTF_8));
  }

  @AfterEach
  void restoreStderr() {
    System.setErr(originalErr);
  }

  @Test
  @DisplayName("hash failure → InternalError carries the underlying Throwable and a WARN log entry")
  void hashFailure_propagatesCause() {
    RuntimeException sentinel = new RuntimeException("PBKDF2 backend missing");
    Fixture fixture = fixtureWith(
        new FailingHashingService(sentinel),
        new RecordingAdministratorStore());

    InitialAdminCreationResult result = fixture.service.createInitialAdmin(
        new CreateInitialAdminCommand(
            fixture.tokenValue,
            "root",
            OK_PASSWORD.toCharArray(),
            "Root",
            "root@example.org"));

    InitialAdminCreationResult.InternalError error =
        assertInstanceOf(InitialAdminCreationResult.InternalError.class, result);
    assertEquals("could not hash password", error.reason());
    assertSame(sentinel, error.cause(),
        "Underlying Throwable must propagate into InternalError.cause()");
    assertWarnLogged("hashing password", sentinel.getMessage());
  }

  @Test
  @DisplayName("persist failure → InternalError carries the underlying Throwable and a WARN log entry")
  void persistFailure_propagatesCause() {
    RuntimeException sentinel = new RuntimeException("storage offline");
    Fixture fixture = fixtureWith(
        PasswordHashingServices.defaults(),
        new FailingAdministratorStore(sentinel));

    InitialAdminCreationResult result = fixture.service.createInitialAdmin(
        new CreateInitialAdminCommand(
            fixture.tokenValue,
            "root",
            OK_PASSWORD.toCharArray(),
            "Root",
            "root@example.org"));

    InitialAdminCreationResult.InternalError error =
        assertInstanceOf(InitialAdminCreationResult.InternalError.class, result);
    assertEquals("could not persist administrator", error.reason());
    assertSame(sentinel, error.cause(),
        "Underlying Throwable must propagate into InternalError.cause()");
    assertWarnLogged("persisting administrator", sentinel.getMessage());
  }

  // ── helpers ────────────────────────────────────────────────────

  private record Fixture(InitialAdminBootstrapService service, String tokenValue) { }

  private Fixture fixtureWith(PasswordHashingService hashing,
                              AdministratorAccountStore store) {
    BootstrapStateService state = new BootstrapStateService(store, BootstrapMode.TRANSIENT_CONSOLE);
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, store, hashing, new MinimumLengthPasswordPolicy(8));
    return new Fixture(service, tokens.load().orElseThrow().value());
  }

  /**
   * The slf4j-simple binding writes WARN entries to System.err in the
   * shape: <code>[thread] WARN logger-name - message</code> followed by
   * the stacktrace when a {@code Throwable} is attached. We assert both
   * the message phrase and the sentinel's message text — the latter
   * proves the {@code Throwable} was passed through to the logger and
   * not silently dropped.
   */
  private void assertWarnLogged(String messagePhrase, String sentinelMessage) {
    String stderr = stderrCapture.toString(StandardCharsets.UTF_8);
    boolean hasWarn = stderr.contains("WARN") && stderr.contains(messagePhrase);
    boolean hasStacktrace = stderr.contains(sentinelMessage);
    assertTrue(hasWarn,
        "Expected WARN log entry containing '" + messagePhrase + "'. Captured:\n" + stderr);
    assertTrue(hasStacktrace,
        "Expected sentinel message '" + sentinelMessage + "' in stacktrace. Captured:\n" + stderr);
  }

  // ── fixtures (no mocks — real classes with deterministic throws) ──

  private static final class FailingHashingService implements PasswordHashingService {
    private final RuntimeException sentinel;
    FailingHashingService(RuntimeException sentinel) { this.sentinel = sentinel; }
    @Override public PasswordHashResult hash(char[] password) {
      throw sentinel;
    }
    @Override public CredentialVerificationResult verify(char[] password, String encodedHash) {
      throw new UnsupportedOperationException("not used in this test");
    }
    @Override public RehashDecision needsRehash(String encodedHash) {
      throw new UnsupportedOperationException("not used in this test");
    }
    @Override public CredentialVerificationResult verifyAgainstNothing(char[] password) {
      throw new UnsupportedOperationException("not used in this test");
    }
  }

  private static final class FailingAdministratorStore implements AdministratorAccountStore {
    private final RuntimeException sentinel;
    FailingAdministratorStore(RuntimeException sentinel) { this.sentinel = sentinel; }
    @Override public boolean hasAnyAdministrator() { return false; }
    @Override public void createAdministrator(NewAdministrator newAdministrator) {
      throw sentinel;
    }
  }

  private static final class RecordingAdministratorStore implements AdministratorAccountStore {
    final List<NewAdministrator> created = new ArrayList<>();
    @Override public synchronized boolean hasAnyAdministrator() { return !created.isEmpty(); }
    @Override public synchronized void createAdministrator(NewAdministrator a) { created.add(a); }
  }
}
