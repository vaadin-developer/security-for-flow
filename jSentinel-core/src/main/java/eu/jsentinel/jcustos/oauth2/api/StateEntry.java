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

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The per-authorization-request state held between the redirect and the callback
 * (V00.77): the PKCE verifier, an optional OIDC nonce (V00.78 uses it), an
 * optional resume target and a creation timestamp for TTL enforcement. The PKCE
 * verifier value is masked in {@link #toString()}.
 *
 * @param pkceVerifier the PKCE {@code code_verifier} bound to this {@code state}
 * @param nonce        the OIDC {@code nonce}, if any (unused in V00.77)
 * @param resumeTarget where to send the user after a successful login, if any
 * @param extra        opaque caller key/value extras
 * @param createdAt    when this entry was created (for TTL)
 * @since 00.77.00
 */
public record StateEntry(
    String pkceVerifier,
    Optional<String> nonce,
    Optional<URI> resumeTarget,
    Map<String, String> extra,
    Instant createdAt) {

  public StateEntry {
    Objects.requireNonNull(pkceVerifier, "pkceVerifier");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(resumeTarget, "resumeTarget");
    extra = Map.copyOf(Objects.requireNonNull(extra, "extra"));
    Objects.requireNonNull(createdAt, "createdAt");
  }

  @Override
  public String toString() {
    return "StateEntry[pkceVerifier=***, nonce=" + (nonce.isPresent() ? "***" : "<none>")
        + ", resumeTarget=" + resumeTarget.map(URI::toString).orElse("<none>")
        + ", createdAt=" + createdAt + "]";
  }
}
