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
import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of {@link AuthorizationCodeFlow#handleCallback} (V00.79.41).
 *
 * <p><strong>JS-SEC-059 (CWE-287 / CWE-294):</strong> earlier releases returned a bare
 * {@link TokenResponse} from the callback, so the OIDC {@code nonce} (and the
 * {@code resumeTarget}) that {@code startRequest} stored in the {@code StateEntry} and sent to
 * the OP were <em>silently dropped</em> on {@code handleCallback}, and the single-use state was
 * consumed — leaving a relying party with no supported way to bind the returned {@code id_token}
 * to the nonce it issued. That made the OIDC nonce defence against id_token replay / cross-session
 * injection unreachable through the API. This record surfaces the stored {@code nonce} and
 * {@code resumeTarget} alongside the tokens, so a caller can enforce the nonce via
 * {@code IdTokenExpectations.of(issuer, audience, callbackResult.nonce())} and resume the user to
 * the originally-requested target.
 *
 * @param tokens       the token-endpoint response (the {@code id_token} slot is still unvalidated
 *                     here — validation, with the nonce below, is the caller's step)
 * @param nonce        the OIDC {@code nonce} bound at {@code startRequest} time, if any
 * @param resumeTarget the post-login target bound at {@code startRequest} time, if any
 * @since 00.79.41
 */
public record CallbackResult(
    TokenResponse tokens,
    Optional<String> nonce,
    Optional<URI> resumeTarget) {

  public CallbackResult {
    Objects.requireNonNull(tokens, "tokens");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(resumeTarget, "resumeTarget");
  }
}
