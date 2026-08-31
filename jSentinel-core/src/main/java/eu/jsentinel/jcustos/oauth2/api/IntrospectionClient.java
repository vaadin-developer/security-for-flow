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
package eu.jsentinel.jcustos.oauth2.api;

import com.svenruppert.functional.result.Result;

/**
 * Token introspection (RFC 7662, V00.77) — the RP asks the authorization server
 * whether an opaque access token is active and what it carries. JOSE-free; the
 * HTTP implementation (with caching) lives in {@code jCustos-oauth2}.
 *
 * @since 00.77.00
 */
public interface IntrospectionClient {

  /**
   * Introspects {@code token}.
   *
   * @param token the token to introspect (never logged)
   * @param hint  the token-type hint
   * @return the introspection result, or a non-secret {@link OAuth2Error}
   */
  Result<IntrospectionResult, OAuth2Error> introspect(String token, TokenTypeHint hint);
}
