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

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;

import java.util.function.Consumer;

/**
 * Common fluent contract shared by every adapter-specific bootstrap
 * facade ({@code VaadinSecurity.bootstrap()}, {@code RestSecurity.bootstrap()},
 * {@code StandaloneSecurity.bootstrap()}).
 * <p>
 * The recursive self-type parameter {@code B} keeps the chain typed: a
 * Vaadin-specific call still returns a {@code VaadinSecurityBootstrap},
 * not the bare common type.
 *
 * @param <B> the concrete builder type (recursive)
 *
 * @since 00.72.00
 */
public interface CommonSecurityBootstrap<B extends CommonSecurityBootstrap<B>> {

  B authentication(AuthenticationService<?, ?> service);

  B authorization(AuthorizationService<?> service);

  B audit(Consumer<AuditBootstrap> config);

  B sessions(Consumer<SessionBootstrap> config);

  B policies(Consumer<PolicyBootstrap> config);

  B roles(Consumer<RoleBootstrap> config);

  B credentials(Consumer<CredentialBootstrap> config);

  B mode(SecurityBootstrapMode mode);

  SecurityRuntime install();
}
