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
package eu.jsentinel.jcustos.dpop;

import com.nimbusds.jose.jwk.JWK;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link DpopKeyStore} (V00.79): a per-target map of DPoP signing keys for a
 * single JVM. Keys are kept only in memory and never logged. Thread-safe.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public final class InMemoryDpopKeyStore implements DpopKeyStore {

  private final Map<String, JWK> keys = new ConcurrentHashMap<>();

  /** Binds {@code key} (which MUST contain its private half) to {@code targetOrigin}. */
  public InMemoryDpopKeyStore put(String targetOrigin, JWK key) {
    Objects.requireNonNull(targetOrigin, "targetOrigin");
    Objects.requireNonNull(key, "key");
    if (!key.isPrivate()) {
      throw new IllegalArgumentException("a DPoP signing key must contain its private half");
    }
    keys.put(targetOrigin, key);
    return this;
  }

  @Override
  public Optional<JWK> keyFor(String targetOrigin) {
    Objects.requireNonNull(targetOrigin, "targetOrigin");
    return Optional.ofNullable(keys.get(targetOrigin));
  }
}
