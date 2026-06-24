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
package com.svenruppert.jsentinel.dx.diagnostics;

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;

import java.lang.annotation.Annotation;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test fixture (registered via {@code META-INF/services}) whose constructor
 * records each instantiation. Lets a test prove that
 * {@link JSentinelDiagnostics#inspect()} enumerates provider <em>types</em>
 * without constructing them (R030). {@link AuthorizationEvaluator} is chosen
 * because no diagnostic rule depends on its presence/absence, so registering
 * one does not perturb the other diagnostics tests.
 */
public final class SideEffectRecordingEvaluator implements AuthorizationEvaluator<Annotation> {

  public static final AtomicInteger INSTANTIATIONS = new AtomicInteger();

  public SideEffectRecordingEvaluator() {
    INSTANTIATIONS.incrementAndGet();
  }

  @Override
  public AuthorizationDecision evaluate(AccessContext context, Annotation annotation) {
    return AuthorizationDecision.granted();
  }
}
