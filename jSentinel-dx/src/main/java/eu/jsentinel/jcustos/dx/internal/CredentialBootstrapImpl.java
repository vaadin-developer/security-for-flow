/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;

import java.util.Objects;

/**
 * Real V00.73 implementation of {@link CredentialBootstrap}.
 *
 * <p>The recording of {@code .modern()} as a flag (rather than an
 * eager classpath probe + instantiation) keeps {@code security-dx}
 * free of a hard runtime dependency on {@code security-crypto-bc}
 * — the probe happens in {@code applyCredentialConfiguration} only
 * when the flag is set.
 *
 * @since 00.73.00
 */
final class CredentialBootstrapImpl implements CredentialBootstrap {

  private final CredentialState state;

  CredentialBootstrapImpl(CredentialState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public CredentialBootstrap passwordHasher(PasswordHasher hasher) {
    state.passwordHasher(Objects.requireNonNull(hasher, "hasher"));
    return this;
  }

  @Override
  public CredentialBootstrap hashing(PasswordHashingService service) {
    state.hashingService(Objects.requireNonNull(service, "service"));
    return this;
  }

  @Override
  public CredentialBootstrap pbkdf2Defaults() {
    state.pbkdf2DefaultsRequested(true);
    return this;
  }

  @Override
  public CredentialBootstrap modern() {
    state.modernRequested(true);
    return this;
  }

  @Override
  public CredentialBootstrap pepper(PepperService service) {
    state.pepperService(Objects.requireNonNull(service, "service"));
    return this;
  }

  @Override
  public CredentialBootstrap credentialStore(CredentialStore store) {
    state.credentialStore(Objects.requireNonNull(store, "store"));
    return this;
  }

  @Override
  public CredentialBootstrap passwordChange(PasswordChangeService service) {
    state.passwordChangeService(Objects.requireNonNull(service, "service"));
    return this;
  }

  @Override
  public CredentialBootstrap passwordReset(
      eu.jsentinel.jcustos.credential.reset.PasswordResetService service) {
    state.passwordResetService(Objects.requireNonNull(service, "service"));
    return this;
  }
}
