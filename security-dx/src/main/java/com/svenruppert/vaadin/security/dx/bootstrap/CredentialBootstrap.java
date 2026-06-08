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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

/**
 * Credential sub-builder of the V00.72 fluent bootstrap.
 * <p>
 * <strong>V00.72 status:</strong> the call is <em>recorded only</em>;
 * no {@code PasswordHashingService} / {@code CredentialStore} wiring
 * is applied through this surface. Real credential wiring is staged
 * for V00.73; V00.71 callers continue to use the existing
 * {@code SecurityServiceResolver.setPasswordHashingService(...)} and
 * the {@code CredentialStore} SPI directly.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public interface CredentialBootstrap {

  CredentialBootstrap pbkdf2Defaults();
}
