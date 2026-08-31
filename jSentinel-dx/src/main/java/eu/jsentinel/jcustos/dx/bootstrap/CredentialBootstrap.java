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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.store.CredentialStore;

/**
 * Credential sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> typed surface — the two
 * credential worlds are kept rigorously separate (Konzept §10):
 * <ul>
 *   <li>{@link #passwordHasher(PasswordHasher)} is the legacy V00.70
 *       resolver path — wired through
 *       {@code JSentinelServiceResolver.setPasswordHashingService(...)}.</li>
 *   <li>{@link #hashing(PasswordHashingService)} is the V00.71
 *       credential-pipeline path — stored in DX state and reported
 *       in {@code JSentinelRuntime}; <strong>never</strong> stuffed
 *       into the legacy setter.</li>
 *   <li>{@link #pbkdf2Defaults()} sets BOTH worlds; {@link #modern()}
 *       sets only the V00.71 pipeline and requires
 *       {@code security-crypto-bc} on the classpath.</li>
 * </ul>
 *
 * <p>{@link #passwordReset(eu.jsentinel.jcustos.credential.reset.PasswordResetService)}
 * references the V00.71 {@code credential.reset.PasswordResetService},
 * NOT the V00.70 {@code accountlifecycle.PasswordResetService}
 * (same simple name; different package). Pick the
 * V00.71 type when importing.
 *
 * @since 00.72.00
 */
public interface CredentialBootstrap {

  CredentialBootstrap passwordHasher(PasswordHasher hasher);

  CredentialBootstrap hashing(PasswordHashingService service);

  /**
   * Convenience: sets both the legacy {@code Pbkdf2PasswordHasher}
   * AND the V00.71 {@code PasswordHashingServices.defaults()}.
   * {@code JSentinelRuntime} reports them as two separate entries —
   * legacy under {@link PasswordHasher}, pipeline under
   * {@link PasswordHashingService}.
   */
  CredentialBootstrap pbkdf2Defaults();

  /**
   * Configures the V00.71 modern (BouncyCastle) password-hashing
   * pipeline. Requires {@code security-crypto-bc} on the classpath;
   * throws {@code JSentinelBootstrapException} with code
   * {@code credentials/modern-without-bc} when the module is missing.
   * Never silently falls back to PBKDF2.
   */
  CredentialBootstrap modern();

  CredentialBootstrap pepper(PepperService service);

  CredentialBootstrap credentialStore(CredentialStore store);

  CredentialBootstrap passwordChange(PasswordChangeService service);

  /**
   * @param service the V00.71
   *                {@code eu.jsentinel.jcustos.credential.reset.PasswordResetService}
   *                (NOT the V00.70
   *                {@code eu.jsentinel.jcustos.accountlifecycle.PasswordResetService}
   *                — same simple name, different package)
   */
  CredentialBootstrap passwordReset(
      eu.jsentinel.jcustos.credential.reset.PasswordResetService service);
}
