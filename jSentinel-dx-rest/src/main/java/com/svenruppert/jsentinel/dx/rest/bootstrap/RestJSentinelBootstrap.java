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
package com.svenruppert.jsentinel.dx.rest.bootstrap;

import com.svenruppert.jsentinel.dx.bootstrap.CommonJSentinelBootstrap;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;

/**
 * REST-specific fluent bootstrap. Entry point:
 * {@link RestSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface RestJSentinelBootstrap
    extends CommonJSentinelBootstrap<RestJSentinelBootstrap> {

  RestJSentinelBootstrap subjectResolver(RestSubjectResolver resolver);

  RestJSentinelBootstrap decisionMapper(RestDecisionMapper mapper);

  RestJSentinelBootstrap errorBodies(RestErrorBodyStrategy strategy);
}
