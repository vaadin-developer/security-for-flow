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
package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;

import java.util.function.Consumer;

/**
 * Common fluent contract shared by every adapter-specific bootstrap
 * facade ({@code VaadinSecurity.bootstrap()}, {@code RestSecurity.bootstrap()},
 * {@code StandaloneSecurity.bootstrap()}).
 * <p>
 * The recursive self-type parameter {@code B} keeps the chain typed: a
 * Vaadin-specific call still returns a {@code VaadinJSentinelBootstrap},
 * not the bare common type.
 *
 * @param <B> the concrete builder type (recursive)
 *
 * @since 00.72.00
 */
public interface CommonJSentinelBootstrap<B extends CommonJSentinelBootstrap<B>> {

  B authentication(AuthenticationService<?, ?> service);

  B authorization(AuthorizationService<?> service);

  B audit(Consumer<AuditBootstrap> config);

  B sessions(Consumer<SessionBootstrap> config);

  B policies(Consumer<PolicyBootstrap> config);

  B roles(Consumer<RoleBootstrap> config);

  B credentials(Consumer<CredentialBootstrap> config);

  B mode(JSentinelBootstrapMode mode);

  JSentinelRuntime install();
}
