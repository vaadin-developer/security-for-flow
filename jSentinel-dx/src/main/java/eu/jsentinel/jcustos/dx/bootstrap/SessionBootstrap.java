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

import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionStore;

import java.time.Duration;

/**
 * Session sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> typed surface — most methods
 * are wired through existing {@code JSentinelServiceResolver}
 * setters. The exception is {@link #storeBacked(SessionStore)}:
 * no global {@code setSessionStore(...)} exists in the V00.71
 * resolver, so the store stays in DX state and is consumed by
 * adapter-DX modules (Vaadin: {@code SessionManagementView}).
 *
 * <p>Adapter symmetry (Konzept §4.1):
 * <ul>
 *   <li>Vaadin — full consumption (policy / version / resolver /
 *       store via SessionManagementView).</li>
 *   <li>REST — policy / version / resolver are consumed;
 *       {@code .storeBacked(...)} is recorded but no-op
 *       ({@code rest/session-store-unused} INFO).</li>
 *   <li>Standalone — every selection produces
 *       {@code standalone/sessions-not-applicable} INFO; the call
 *       is accepted to keep the API symmetric.</li>
 * </ul>
 *
 * <p>{@link #subjectIdResolver(SubjectIdResolver)} lives here
 * because V00.70/V00.71 use {@code SubjectIdResolver} only for
 * {@code JSentinelVersion} drift detection — a session concept
 * (Konzept §7.3).
 *
 * @since 00.72.00
 */
public interface SessionBootstrap {

  SessionBootstrap storeBacked(SessionStore store);

  SessionBootstrap securityVersion(JSentinelVersionStore store);

  SessionBootstrap subjectIdResolver(SubjectIdResolver<?> resolver);

  SessionBootstrap timeout(Duration idleTimeout);

  SessionBootstrap absoluteLifetime(Duration absoluteTimeout);

  SessionBootstrap policy(SessionPolicy<?> policy);
}
