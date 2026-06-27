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

import com.nimbusds.jose.jwk.JWK;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Optional;

/**
 * Holds the client's per-target DPoP signing keys (V00.79). A DPoP client SHOULD use a
 * distinct key per authorization/resource server so a proof captured by one cannot be
 * replayed against another (RFC 9449 §11.1). The returned key MUST contain its private
 * half (it signs proofs). Implementations MUST be thread-safe.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public interface DpopKeyStore {

  /** The signing key bound to {@code targetOrigin} (e.g. {@code https://api.example.com}). */
  Optional<JWK> keyFor(String targetOrigin);
}
