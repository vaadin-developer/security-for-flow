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
package com.svenruppert.vaadin.security.dx.standalone.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.dx.bootstrap.CommonJSentinelBootstrap;

/**
 * Standalone-specific fluent bootstrap. Entry point:
 * {@link StandaloneSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface StandaloneJSentinelBootstrap
    extends CommonJSentinelBootstrap<StandaloneJSentinelBootstrap> {

  StandaloneJSentinelBootstrap subjectStore(SubjectStore store);

  StandaloneJSentinelBootstrap loginAttemptPolicy(LoginAttemptPolicy policy);
}
