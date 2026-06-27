/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
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
package com.svenruppert.jsentinel.dpop;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * The inbound request context a {@link DpopProofValidator} validates a proof against
 * (V00.79): the raw {@code DPoP} header value, the actual HTTP method + request URI
 * the proof must bind to ({@code htm} / {@code htu}, RFC 9449 §4.3), and — when the
 * proof accompanies a DPoP-bound access token at a resource server — that access
 * token so the {@code ath} claim can be checked (§4.3 step 12).
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public record DpopValidationRequest(
    String proofCompact,
    String httpMethod,
    URI httpUri,
    Optional<String> accessToken) {

  public DpopValidationRequest {
    Objects.requireNonNull(proofCompact, "proofCompact");
    Objects.requireNonNull(httpMethod, "httpMethod");
    Objects.requireNonNull(httpUri, "httpUri");
    Objects.requireNonNull(accessToken, "accessToken");
  }

  /** A request that validates the binding only (no access-token {@code ath} check). */
  public static DpopValidationRequest of(String proofCompact, String httpMethod, URI httpUri) {
    return new DpopValidationRequest(proofCompact, httpMethod, httpUri, Optional.empty());
  }

  /** A request that also checks the proof's {@code ath} against {@code accessToken}. */
  public static DpopValidationRequest boundTo(
      String proofCompact, String httpMethod, URI httpUri, String accessToken) {
    return new DpopValidationRequest(proofCompact, httpMethod, httpUri, Optional.of(accessToken));
  }
}
