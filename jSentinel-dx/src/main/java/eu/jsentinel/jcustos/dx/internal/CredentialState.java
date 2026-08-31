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
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.store.CredentialStore;

/**
 * Sub-aggregate of {@link BootstrapState} for credential
 * configuration. Keeps legacy and V00.71-pipeline state in
 * separate slots (Konzept §10).
 *
 * @since 00.73.00
 */
public final class CredentialState {

  // legacy resolver-path
  private PasswordHasher passwordHasher;

  // V00.71 pipeline
  private PasswordHashingService hashingService;
  private PepperService pepperService;
  private CredentialStore credentialStore;
  private PasswordChangeService passwordChangeService;
  private PasswordResetService passwordResetService;

  // semantics flags
  private boolean modernRequested;
  private boolean pbkdf2DefaultsRequested;

  public PasswordHasher passwordHasher() {
    return passwordHasher;
  }

  public void passwordHasher(PasswordHasher hasher) {
    this.passwordHasher = hasher;
  }

  public PasswordHashingService hashingService() {
    return hashingService;
  }

  public void hashingService(PasswordHashingService service) {
    this.hashingService = service;
  }

  public PepperService pepperService() {
    return pepperService;
  }

  public void pepperService(PepperService service) {
    this.pepperService = service;
  }

  public CredentialStore credentialStore() {
    return credentialStore;
  }

  public void credentialStore(CredentialStore store) {
    this.credentialStore = store;
  }

  public PasswordChangeService passwordChangeService() {
    return passwordChangeService;
  }

  public void passwordChangeService(PasswordChangeService service) {
    this.passwordChangeService = service;
  }

  public PasswordResetService passwordResetService() {
    return passwordResetService;
  }

  public void passwordResetService(PasswordResetService service) {
    this.passwordResetService = service;
  }

  public boolean modernRequested() {
    return modernRequested;
  }

  public void modernRequested(boolean v) {
    this.modernRequested = v;
  }

  public boolean pbkdf2DefaultsRequested() {
    return pbkdf2DefaultsRequested;
  }

  public void pbkdf2DefaultsRequested(boolean v) {
    this.pbkdf2DefaultsRequested = v;
  }
}
