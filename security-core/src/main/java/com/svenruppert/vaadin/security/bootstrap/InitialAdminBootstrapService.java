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

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
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

  private final BootstrapStateService stateService;
  private final BootstrapTokenStore tokenStore;
  private final AdministratorAccountStore administratorStore;
  private final PasswordHasher passwordHasher;
  private final PasswordPolicy passwordPolicy;
  private final ReentrantLock lock = new ReentrantLock();

  public InitialAdminBootstrapService(
      BootstrapStateService stateService,
      BootstrapTokenStore tokenStore,
      AdministratorAccountStore administratorStore,
      PasswordHasher passwordHasher,
      PasswordPolicy passwordPolicy) {
    this.stateService = Objects.requireNonNull(stateService);
    this.tokenStore = Objects.requireNonNull(tokenStore);
    this.administratorStore = Objects.requireNonNull(administratorStore);
    this.passwordHasher = Objects.requireNonNull(passwordHasher);
    this.passwordPolicy = Objects.requireNonNull(passwordPolicy);
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
        if (stored.isEmpty() || !stored.get().matches(command.bootstrapToken())) {
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
          passwordHash = passwordHasher.hash(command.password());
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
          // setup succeeded; deletion failed — never echo the token
          return new InitialAdminCreationResult.Created(command.username());
        }
        return new InitialAdminCreationResult.Created(command.username());
      } finally {
        lock.unlock();
      }
    } finally {
      Arrays.fill(command.password(), '\0');
    }
  }
}
