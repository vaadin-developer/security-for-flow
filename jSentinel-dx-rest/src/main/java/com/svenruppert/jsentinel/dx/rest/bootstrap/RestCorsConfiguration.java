/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.dx.rest.bootstrap;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.List;

/**
 * Immutable snapshot of the CORS settings collected by
 * {@link RestCorsConfigurationBuilder}. Published via
 * {@link RestCorsContext}; downstream REST glue code (a servlet
 * filter, the demo server, etc.) consumes it to render the
 * {@code Access-Control-*} headers.
 *
 * <p>The library does not ship a CORS filter — that's framework
 * territory. This DTO + the static holder are the integration
 * point.
 *
 * @param allowedOrigins      origins to echo back into
 *                            {@code Access-Control-Allow-Origin};
 *                            wildcard {@code "*"} permitted
 * @param allowedMethods      methods echoed in
 *                            {@code Access-Control-Allow-Methods}
 * @param allowedHeaders      headers echoed in
 *                            {@code Access-Control-Allow-Headers}
 * @param exposedHeaders      headers exposed via
 *                            {@code Access-Control-Expose-Headers}
 * @param allowCredentials    whether to emit
 *                            {@code Access-Control-Allow-Credentials: true}
 * @param maxAgeSeconds       value for {@code Access-Control-Max-Age};
 *                            {@code -1} suppresses the header
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record RestCorsConfiguration(
    List<String> allowedOrigins,
    List<String> allowedMethods,
    List<String> allowedHeaders,
    List<String> exposedHeaders,
    boolean allowCredentials,
    long maxAgeSeconds
) {

  /** Defensive copies on construction. */
  public RestCorsConfiguration {
    allowedOrigins = List.copyOf(allowedOrigins);
    allowedMethods = List.copyOf(allowedMethods);
    allowedHeaders = List.copyOf(allowedHeaders);
    exposedHeaders = List.copyOf(exposedHeaders);
  }

  /**
   * Whether this snapshot is the dangerous credentialed-wildcard combination —
   * {@code Access-Control-Allow-Credentials: true} together with a wildcard
   * {@code "*"} origin. That pair is forbidden by the CORS spec (browsers reject
   * it) and, if a server reflected it, an account-takeover hole. The bootstrap
   * uses this to warn in every mode, throw in STRICT, and — R15 (V00.76.10) —
   * refuse to publish it live in PRODUCTION.
   *
   * @return {@code true} iff credentials are allowed alongside a wildcard origin
   */
  public boolean isCredentialedWildcard() {
    return allowCredentials && allowedOrigins.contains("*");
  }
}
