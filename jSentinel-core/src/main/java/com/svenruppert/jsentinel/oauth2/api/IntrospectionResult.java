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
package com.svenruppert.jsentinel.oauth2.api;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The result of a token introspection (RFC 7662 §2.2, V00.77). For an opaque
 * access token this is the RP's only way to learn its validity + metadata. The
 * only mandatory field is {@link #active()}; everything else is present only
 * when the introspection endpoint returns it.
 *
 * @since 00.77.00
 */
public record IntrospectionResult(
    boolean active,
    Set<String> scope,
    Optional<String> clientId,
    Optional<String> username,
    Optional<Instant> expiresAt,
    Optional<Instant> issuedAt,
    Optional<String> tokenType,
    Set<String> audience,
    Optional<String> issuer,
    Optional<String> jti) {

  public IntrospectionResult {
    scope = Set.copyOf(Objects.requireNonNull(scope, "scope"));
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(tokenType, "tokenType");
    // JS-SEC-043 (CWE-20): audience is a Set, not Optional<String> — RFC 7662 §2.2 permits `aud`
    // as a JSON string OR an array of strings (Keycloak/Auth0/Okta emit the array), which an
    // Optional<String> silently dropped. A consumer that enforces audience must treat an EMPTY
    // set as fail-closed for its own resource server, not accept-if-absent.
    audience = Set.copyOf(Objects.requireNonNull(audience, "audience"));
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(jti, "jti");
  }

  /** An inactive (rejected) introspection result. */
  public static IntrospectionResult inactive() {
    return new IntrospectionResult(false, Set.of(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.empty(), Set.of(),
        Optional.empty(), Optional.empty());
  }
}
