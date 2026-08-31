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
package eu.jsentinel.jcustos.bootstrap;

/**
 * Outcome of {@link InitialAdminBootstrapService#createInitialAdmin}.
 */
public sealed interface InitialAdminCreationResult
    permits InitialAdminCreationResult.Created,
            InitialAdminCreationResult.AlreadyInitialized,
            InitialAdminCreationResult.InvalidBootstrapToken,
            InitialAdminCreationResult.PasswordPolicyViolation,
            InitialAdminCreationResult.InvalidUsername,
            InitialAdminCreationResult.InternalError {

  record Created(String username) implements InitialAdminCreationResult {
  }

  record AlreadyInitialized() implements InitialAdminCreationResult {
  }

  record InvalidBootstrapToken() implements InitialAdminCreationResult {
  }

  record PasswordPolicyViolation(String reason) implements InitialAdminCreationResult {
  }

  record InvalidUsername(String reason) implements InitialAdminCreationResult {
  }

  /**
   * Service-internal failure. {@code reason} is a generic, non-leaking
   * message safe to surface to end users. {@code cause} carries the
   * underlying {@link Throwable} for diagnostics; the framework guarantees
   * it is also written to the service log at WARNING level with the full
   * stacktrace, so operators can debug even when the consumer drops the
   * cause silently.
   *
   * @apiNote {@code cause} may be {@code null} when no underlying throwable
   *          exists. It is intentionally not wrapped in
   *          {@link java.util.Optional} — the sealed-result discipline
   *          encodes optionality structurally, and a nullable field keeps
   *          the call-site lean. Consumers should pattern-match on
   *          {@code InternalError(reason, cause)} and treat
   *          {@code cause == null} as &quot;no underlying throwable&quot;.
   * @since 00.74.10
   */
  record InternalError(String reason, Throwable cause) implements InitialAdminCreationResult {
  }
}
