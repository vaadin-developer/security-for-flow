/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.credential.propagation;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Map;
import java.util.Objects;

/**
 * Input record for {@link OutboundTokenStrategy#resolve(OutboundCall,
 * java.util.Optional)}. Describes the call the wrapper is about to
 * issue.
 *
 * <p>{@code hints} is a free-form extension point; strategies look up
 * specific keys (e.g. {@code "scope"} for client-credentials flows). The
 * canonical constructor takes a defensive {@link Map#copyOf(Map)} copy so
 * mutating the source map after construction does not leak into the
 * record.
 *
 * @param targetServiceName logical name of the downstream service
 *                          (e.g. interface simple name)
 * @param methodName        method being called
 * @param declaredAudience  declared audience from
 *                          {@code @PropagateToken(audience = ...)}; empty
 *                          when not declared
 * @param hints             extension-point key/value pairs
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record OutboundCall(
    String targetServiceName,
    String methodName,
    String declaredAudience,
    Map<String, String> hints) {

  public OutboundCall {
    Objects.requireNonNull(targetServiceName, "targetServiceName");
    Objects.requireNonNull(methodName, "methodName");
    Objects.requireNonNull(declaredAudience, "declaredAudience");
    Objects.requireNonNull(hints, "hints");
    hints = Map.copyOf(hints);
  }
}
