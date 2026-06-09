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

import com.svenruppert.vaadin.security.audit.BootstrapAdminCreated;
import com.svenruppert.vaadin.security.audit.BootstrapTokenRejected;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingService;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Single-entry orchestrator that converts a {@link CreateInitialAdminCommand}
 * into either a freshly created administrator or a non-leaking failure
 * code.
 * <p>
 * The double-check + create + invalidate sequence runs inside a
 * {@link ReentrantLock}, so two parallel setup requests cannot both create
 * an administrator. The {@code password} array is wiped before the method
 * returns regardless of outcome.
 */
public final class InitialAdminBootstrapService {

  private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9._-]{1,64}");
  private static final Logger LOGGER = Logger.getLogger(InitialAdminBootstrapService.class.getName());

  private final BootstrapStateService stateService;
  private final BootstrapTokenStore tokenStore;
  private final AdministratorAccountStore administratorStore;
  private final PasswordHashingService passwordHashingService;
  private final PasswordPolicy passwordPolicy;
  private final Duration tokenValidity;
  private final Clock clock;
  private final ReentrantLock lock = new ReentrantLock();

  public InitialAdminBootstrapService(
      BootstrapStateService stateService,
      BootstrapTokenStore tokenStore,
      AdministratorAccountStore administratorStore,
      PasswordHashingService passwordHashingService,
      PasswordPolicy passwordPolicy) {
    this(stateService, tokenStore, administratorStore, passwordHashingService, passwordPolicy,
        BootstrapConfiguration.DEFAULT_VALIDITY, Clock.systemUTC());
  }

  public InitialAdminBootstrapService(
      BootstrapStateService stateService,
      BootstrapTokenStore tokenStore,
      AdministratorAccountStore administratorStore,
      PasswordHashingService passwordHashingService,
      PasswordPolicy passwordPolicy,
      Duration tokenValidity,
      Clock clock) {
    this.stateService = Objects.requireNonNull(stateService);
    this.tokenStore = Objects.requireNonNull(tokenStore);
    this.administratorStore = Objects.requireNonNull(administratorStore);
    this.passwordHashingService = Objects.requireNonNull(passwordHashingService);
    this.passwordPolicy = Objects.requireNonNull(passwordPolicy);
    this.tokenValidity = Objects.requireNonNull(tokenValidity);
    this.clock = Objects.requireNonNull(clock);
  }

  public InitialAdminCreationResult createInitialAdmin(CreateInitialAdminCommand command) {
    Objects.requireNonNull(command, "command");
    try {
      lock.lock();
      try {
        if (!stateService.bootstrapRequired()) {
          return new InitialAdminCreationResult.AlreadyInitialized();
        }
        if (administratorStore.hasAnyAdministrator()) {
          return new InitialAdminCreationResult.AlreadyInitialized();
        }
        Optional<BootstrapToken> stored = tokenStore.load();
        if (stored.isEmpty()) {
          auditTokenRejected("Unknown");
          return new InitialAdminCreationResult.InvalidBootstrapToken();
        }
        if (!stored.get().matches(command.bootstrapToken())) {
          auditTokenRejected("Mismatch");
          return new InitialAdminCreationResult.InvalidBootstrapToken();
        }
        if (stored.get().isExpired(clock.instant(), tokenValidity)) {
          // Expired tokens are treated like invalid ones — same outcome,
          // generic message. Persistent mode regenerates on next startup.
          auditTokenRejected("Expired");
          return new InitialAdminCreationResult.InvalidBootstrapToken();
        }
        if (command.username() == null
            || !USERNAME.matcher(command.username()).matches()) {
          return new InitialAdminCreationResult.InvalidUsername(
              "username must be 1-64 chars of [A-Za-z0-9._-]");
        }
        var policyResult = passwordPolicy.validate(command.password());
        if (!policyResult.valid()) {
          return new InitialAdminCreationResult.PasswordPolicyViolation(policyResult.reason());
        }
        String passwordHash;
        try {
          PasswordHashResult result = passwordHashingService.hash(command.password());
          passwordHash = result.encodedHash();
        } catch (RuntimeException e) {
          return new InitialAdminCreationResult.InternalError("could not hash password");
        }
        try {
          administratorStore.createAdministrator(new NewAdministrator(
              command.username(),
              command.displayName(),
              command.email(),
              passwordHash));
        } catch (RuntimeException e) {
          return new InitialAdminCreationResult.InternalError("could not persist administrator");
        }
        try {
          tokenStore.invalidate();
        } catch (RuntimeException e) {
          // Setup succeeded but the token store could not be cleaned up.
          // Surface a clear warning (without ever printing the token value)
          // so operators can manually remove the stale token file.
          LOGGER.log(Level.WARNING,
              "Bootstrap setup completed for user '" + command.username()
                  + "' but invalidating the bootstrap token failed. "
                  + "Manual cleanup of the token store is required. "
                  + "(The token value is never logged.)",
              e);
          auditAdminCreated(command.username());
          return new InitialAdminCreationResult.Created(command.username());
        }
        auditAdminCreated(command.username());
        return new InitialAdminCreationResult.Created(command.username());
      } finally {
        lock.unlock();
      }
    } finally {
      Arrays.fill(command.password(), '\0');
    }
  }

  private void auditAdminCreated(String username) {
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(new BootstrapAdminCreated(Instant.now(clock), username, null));
    } catch (RuntimeException ignored) {
      // never block bootstrap because the audit sink failed
    }
  }

  private void auditTokenRejected(String reason) {
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(new BootstrapTokenRejected(Instant.now(clock), reason, null));
    } catch (RuntimeException ignored) {
      // never block bootstrap because the audit sink failed
    }
  }
}
