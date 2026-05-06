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
package com.svenruppert.vaadin.security.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("InitialAdminBootstrapService")
class InitialAdminBootstrapServiceTest {

  private static final String OK_PASSWORD = "correct horse battery staple";

  // ── Helpers ────────────────────────────────────────────────────

  private static InitialAdminBootstrapService transientService(FakeAdministratorStore admins) {
    BootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    return new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));
  }

  private static String tokenIn(InMemoryBootstrapTokenStore store) {
    return store.load().orElseThrow().value();
  }

  // ── Tests ──────────────────────────────────────────────────────

  @Test
  @DisplayName("token is generated when system is uninitialized (transient)")
  void transientGeneratesTokenOnStartup() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(stdout), ""),
        BootstrapConfiguration.transientConsole());
    assertTrue(tokens.load().isPresent());
    String banner = stdout.toString(StandardCharsets.UTF_8);
    assertTrue(banner.contains("Bootstrap token:"));
    assertTrue(banner.contains(tokens.load().orElseThrow().value()));
  }

  @Test
  @DisplayName("no token is generated when an administrator already exists")
  void noTokenWhenAdminExists() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    admins.createAdministrator(new NewAdministrator("root", "Root", null, "pbkdf2$1$AA$BB"));
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStartup.initializeIfRequired(
        new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE),
        tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    assertTrue(tokens.load().isEmpty());
  }

  @Test
  @DisplayName("persistent mode writes the token file and reuses it after restart")
  void persistentReuseAfterRestart(@TempDir Path tmp) {
    Path tokenFile = tmp.resolve("data/bootstrap.token");
    FakeAdministratorStore admins = new FakeAdministratorStore();
    BootstrapConfiguration cfg = BootstrapConfiguration.persistent(tokenFile);

    BootstrapTokenStore tokens1 = new FileBootstrapTokenStore(tokenFile);
    BootstrapStartup.initializeIfRequired(
        new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE),
        tokens1, new BootstrapTokenGenerator(),
        new FileBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream())),
        cfg);
    assertTrue(Files.exists(tokenFile));
    String first = tokens1.load().orElseThrow().value();

    // simulate restart with a brand new store pointing at the same file
    BootstrapTokenStore tokens2 = new FileBootstrapTokenStore(tokenFile);
    BootstrapStartup.initializeIfRequired(
        new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE),
        tokens2, new BootstrapTokenGenerator(),
        new FileBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream())),
        cfg);
    assertEquals(first, tokens2.load().orElseThrow().value(),
        "Persistent mode must reuse the existing token across restarts");
  }

  @Test
  @DisplayName("persistent mode deletes the token file after successful setup")
  void persistentDeletesAfterSetup(@TempDir Path tmp) {
    Path tokenFile = tmp.resolve("bootstrap.token");
    FakeAdministratorStore admins = new FakeAdministratorStore();
    BootstrapTokenStore tokens = new FileBootstrapTokenStore(tokenFile);
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new FileBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream())),
        BootstrapConfiguration.persistent(tokenFile));
    String token = tokens.load().orElseThrow().value();

    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));
    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand(token, "root", OK_PASSWORD.toCharArray(), "Root", null));

    assertInstanceOf(InitialAdminCreationResult.Created.class, result);
    assertFalse(Files.exists(tokenFile), "Token file must be deleted after successful setup");
  }

  @Test
  @DisplayName("transient mode keeps the token only in memory")
  void transientStoresInMemoryOnly(@TempDir Path tmp) {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStartup.initializeIfRequired(
        new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE),
        tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());

    // No file is touched anywhere
    assertEquals(0, tmp.toFile().list().length);
    assertTrue(tokens.load().isPresent());
  }

  @Test
  @DisplayName("invalid token is rejected")
  void invalidTokenRejected() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InitialAdminBootstrapService service = transientService(admins);
    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand("WRONG-TOKEN-VALUE-HERE", "root",
            OK_PASSWORD.toCharArray(), "Root", null));
    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class, result);
    assertFalse(admins.hasAnyAdministrator());
  }

  @Test
  @DisplayName("token cannot be used twice")
  void tokenSingleUse() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    String token = tokenIn(tokens);

    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));

    var first = service.createInitialAdmin(
        new CreateInitialAdminCommand(token, "root", OK_PASSWORD.toCharArray(), "Root", null));
    assertInstanceOf(InitialAdminCreationResult.Created.class, first);

    var second = service.createInitialAdmin(
        new CreateInitialAdminCommand(token, "root2", OK_PASSWORD.toCharArray(), "Root", null));
    // After setup the system reports already-initialized — token never reaches validation
    assertInstanceOf(InitialAdminCreationResult.AlreadyInitialized.class, second);
  }

  @Test
  @DisplayName("setup is rejected after an administrator exists")
  void rejectedAfterAdminExists() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InitialAdminBootstrapService service = transientService(admins);
    admins.createAdministrator(new NewAdministrator("root", "Root", null, "pbkdf2$1$A$B"));
    var result = service.createInitialAdmin(
        new CreateInitialAdminCommand("ANY-TOKEN", "second", OK_PASSWORD.toCharArray(), "Second", null));
    assertInstanceOf(InitialAdminCreationResult.AlreadyInitialized.class, result);
  }

  @Test
  @DisplayName("password policy violation is reported")
  void shortPasswordRejected() {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));
    var result = service.createInitialAdmin(
        new CreateInitialAdminCommand(tokenIn(tokens), "root", "short".toCharArray(), "Root", null));
    assertInstanceOf(InitialAdminCreationResult.PasswordPolicyViolation.class, result);
  }

  @Test
  @DisplayName("parallel initial admin creation results in exactly one administrator")
  void parallelCreation() throws Exception {
    FakeAdministratorStore admins = new FakeAdministratorStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());
    String token = tokenIn(tokens);
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));

    int parallel = 16;
    ExecutorService pool = Executors.newFixedThreadPool(parallel);
    CountDownLatch start = new CountDownLatch(1);
    List<java.util.concurrent.Future<InitialAdminCreationResult>> futures = new ArrayList<>();
    for (int i = 0; i < parallel; i++) {
      final int idx = i;
      futures.add(pool.submit(() -> {
        start.await();
        return service.createInitialAdmin(new CreateInitialAdminCommand(
            token, "root" + idx, OK_PASSWORD.toCharArray(), "Root", null));
      }));
    }
    start.countDown();
    pool.shutdown();
    pool.awaitTermination(10, TimeUnit.SECONDS);

    AtomicInteger created = new AtomicInteger();
    for (var future : futures) {
      InitialAdminCreationResult r = future.get();
      if (r instanceof InitialAdminCreationResult.Created) created.incrementAndGet();
    }
    assertEquals(1, created.get(), "Exactly one Created result expected");
    assertEquals(1, admins.adminCount(), "Exactly one administrator expected");
  }

  // ── Test fixture ──────────────────────────────────────────────

  static final class FakeAdministratorStore implements AdministratorAccountStore {
    private final List<NewAdministrator> admins = new ArrayList<>();

    @Override
    public synchronized boolean hasAnyAdministrator() {
      return !admins.isEmpty();
    }

    @Override
    public synchronized void createAdministrator(NewAdministrator newAdministrator) {
      admins.add(newAdministrator);
    }

    synchronized int adminCount() {
      return admins.size();
    }
  }
}
