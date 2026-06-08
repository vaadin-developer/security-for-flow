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
package com.svenruppert.vaadin.security.dx.rest.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.dx.bootstrap.CommonSecurityBootstrap;
import com.svenruppert.vaadin.security.rest.RestSubjectResolver;

/**
 * REST-specific fluent bootstrap. Entry point:
 * {@link RestSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public interface RestSecurityBootstrap
    extends CommonSecurityBootstrap<RestSecurityBootstrap> {

  RestSecurityBootstrap subjectResolver(RestSubjectResolver resolver);

  RestSecurityBootstrap decisionMapper(RestDecisionMapper mapper);

  RestSecurityBootstrap errorBodies(RestErrorBodyStrategy strategy);
}
