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
package eu.jsentinel.jcustos.jwt.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Objects;
import java.util.Set;

/**
 * The explicit allow-lists a {@link JweDecoder} enforces (V00.79, RFC 7516): permitted
 * {@code alg} (key-management) and {@code enc} (content-encryption) header values. An
 * empty intersection with the proof header is a hard reject — there is no implicit
 * fallback, so {@code alg:dir} / {@code RSA1_5} downgrade attacks cannot slip through.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public record JweAlgorithmAllowList(Set<String> keyManagement, Set<String> contentEncryption) {

  public JweAlgorithmAllowList {
    keyManagement = Set.copyOf(Objects.requireNonNull(keyManagement, "keyManagement"));
    contentEncryption = Set.copyOf(Objects.requireNonNull(contentEncryption, "contentEncryption"));
    if (keyManagement.isEmpty() || contentEncryption.isEmpty()) {
      throw new IllegalArgumentException("JWE allow-lists must be non-empty");
    }
  }

  public boolean allowsKeyManagement(String alg) {
    return keyManagement.contains(alg);
  }

  public boolean allowsContentEncryption(String enc) {
    return contentEncryption.contains(enc);
  }

  /** Modern default: {@code RSA-OAEP-256} key-management, {@code A128GCM}/{@code A256GCM} content. */
  public static JweAlgorithmAllowList defaults() {
    return new JweAlgorithmAllowList(Set.of("RSA-OAEP-256"), Set.of("A128GCM", "A256GCM"));
  }

  /** FIPS 140-3 profile: {@code RSA-OAEP-256} key-management, {@code A256GCM} content only. */
  public static JweAlgorithmAllowList fips() {
    return new JweAlgorithmAllowList(Set.of("RSA-OAEP-256"), Set.of("A256GCM"));
  }
}
