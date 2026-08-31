/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.policy;

import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;

import java.util.Map;
import java.util.Set;

/**
 * Active password-hashing policy.
 *
 * <p>The policy is the single source of truth for which algorithm,
 * provider and parameters are used for newly produced hashes and which
 * envelope shapes are accepted on verify. It also defines the
 * <em>minimum</em> and <em>maximum</em> parameter bounds that the
 * validator enforces before any KDF runs.</p>
 *
 * <p>The policy is intentionally adapter-neutral: it never references
 * Vaadin, HTTP, JPA or specific provider implementations.</p>
 */
public interface PasswordHashPolicy {

  /**
   * Monotonically increasing version of this policy. Stored in every
   * envelope. A mismatch between the active policy version and the
   * version embedded in an envelope is one of the triggers for a
   * {@code POLICY_VERSION_OUTDATED} rehash.
   */
  int policyVersion();

  /**
   * Envelope wire format the policy emits for new hashes. Older known
   * format versions remain readable but may be flagged for rehash.
   */
  PasswordHashFormatVersion preferredFormatVersion();

  /**
   * Algorithm identifier the policy emits for new hashes.
   */
  String preferredAlgorithm();

  /**
   * Provider identifier the policy emits for new hashes.
   */
  String preferredProviderId();

  /**
   * Returns whether the given algorithm is acceptable for verification
   * under this policy.
   */
  boolean isAlgorithmAcceptable(String algorithm);

  /**
   * Returns whether the given provider identifier is acceptable for
   * verification under this policy.
   */
  boolean isProviderAcceptable(String providerId);

  /**
   * Algorithm identifiers that are still accepted by this policy. The
   * preferred algorithm is always part of this set.
   */
  Set<String> acceptableAlgorithms();

  /**
   * Provider identifiers that are still accepted by this policy. The
   * preferred provider is always part of this set.
   */
  Set<String> acceptableProviderIds();

  /**
   * Default parameters the policy emits when producing a fresh hash
   * with the given algorithm.
   *
   * @throws PasswordHashValidationException if the algorithm is unknown
   *                                          to this policy
   */
  Map<String, String> defaultParameters(String algorithm);

  /**
   * Lower bound for each parameter value. Validation rejects envelopes
   * whose parameters fall below these values.
   *
   * @throws PasswordHashValidationException if the algorithm is unknown
   *                                          to this policy
   */
  Map<String, String> minimumParameters(String algorithm);

  /**
   * Upper bound for each parameter value. Validation rejects envelopes
   * whose parameters exceed these values; this is the primary defence
   * against parameter-driven resource exhaustion (CWE-400).
   *
   * @throws PasswordHashValidationException if the algorithm is unknown
   *                                          to this policy
   */
  Map<String, String> maximumParameters(String algorithm);

  /**
   * Envelope format versions the operator has explicitly rejected.
   * Envelopes whose {@code formatVersion} appears here fail validation
   * outright; older versions that are <em>not</em> in this set remain
   * verifiable and are flagged for rehash by the rehash engine.
   *
   * <p>Default: empty (no formats explicitly rejected).</p>
   */
  default Set<Integer> rejectedFormatVersions() {
    return Set.of();
  }

  /**
   * Policy versions the operator has explicitly rejected.
   * Envelopes whose {@code policyVersion} appears here fail validation
   * outright; older versions that are not in this set remain verifiable
   * (and are flagged for rehash if they are below the active policy
   * version).
   *
   * <p>Default: empty (no policy versions explicitly rejected).</p>
   */
  default Set<Integer> rejectedPolicyVersions() {
    return Set.of();
  }
}
