/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.metrics;

import eu.jsentinel.jcustos.credential.abuse.AbusePattern;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;

import java.util.Objects;

/**
 * Sealed family of data-minimised metric events emitted by
 * security-core. The shape matches Konzept §16: durations,
 * algorithm/policy distributions, counters — never the password
 * material, salt, derived key, pepper key value, username or client
 * address (CWE-532 / CWE-359).
 *
 * <p>Adapters export these to whichever metrics backend they like
 * (Micrometer, OpenTelemetry, Prometheus, custom Statsd). The core
 * stays backend-free.</p>
 */
public sealed interface CredentialMetricEvent
    permits CredentialMetricEvent.HashDuration,
            CredentialMetricEvent.VerifyDuration,
            CredentialMetricEvent.RehashRequested,
            CredentialMetricEvent.LifecycleTransition,
            CredentialMetricEvent.AbuseSignal,
            CredentialMetricEvent.KdfLimiterRejection {

  /**
   * One {@code PasswordHashingService.hash} call completed.
   *
   * @param algorithm     algorithm identifier used
   * @param providerId    provider identifier used
   * @param policyVersion policy version under which the hash was
   *                      produced
   * @param durationMicros wall-clock duration in microseconds
   * @param peppered      whether the result envelope carried a pepper
   *                      key id
   */
  record HashDuration(
      String algorithm,
      String providerId,
      int policyVersion,
      long durationMicros,
      boolean peppered
  ) implements CredentialMetricEvent {
    public HashDuration {
      Objects.requireNonNull(algorithm, "algorithm");
      Objects.requireNonNull(providerId, "providerId");
      if (durationMicros < 0L) {
        throw new IllegalArgumentException("durationMicros must be >= 0");
      }
    }
  }

  /**
   * One {@code PasswordHashingService.verify} call completed.
   *
   * @param algorithm      algorithm of the stored envelope
   * @param providerId     provider id of the stored envelope
   * @param policyVersion  policy version recorded in the envelope
   * @param durationMicros wall-clock duration in microseconds
   * @param verified       whether the verification succeeded
   * @param dummyPath      whether the dummy KDF ran instead of a real
   *                       verification (unknown user / malformed
   *                       envelope / missing provider / unknown
   *                       pepper key)
   */
  record VerifyDuration(
      String algorithm,
      String providerId,
      int policyVersion,
      long durationMicros,
      boolean verified,
      boolean dummyPath
  ) implements CredentialMetricEvent {
    public VerifyDuration {
      Objects.requireNonNull(algorithm, "algorithm");
      Objects.requireNonNull(providerId, "providerId");
      if (durationMicros < 0L) {
        throw new IllegalArgumentException("durationMicros must be >= 0");
      }
    }
  }

  /**
   * A successful verification triggered a transparent rehash.
   */
  record RehashRequested(RehashReason reason)
      implements CredentialMetricEvent {
    public RehashRequested {
      Objects.requireNonNull(reason, "reason");
    }
  }

  /**
   * A credential moved between lifecycle states.
   *
   * @param fromStatus prior status
   * @param toStatus   new status
   */
  record LifecycleTransition(
      CredentialStatus fromStatus, CredentialStatus toStatus)
      implements CredentialMetricEvent {
    public LifecycleTransition {
      Objects.requireNonNull(fromStatus, "fromStatus");
      Objects.requireNonNull(toStatus, "toStatus");
    }
  }

  /**
   * Abuse pattern detector fired. Carries the aggregate
   * (distinctTargets, attempts) — never the targets themselves.
   */
  record AbuseSignal(AbusePattern pattern, int distinctTargets, int attempts)
      implements CredentialMetricEvent {
    public AbuseSignal {
      Objects.requireNonNull(pattern, "pattern");
      if (distinctTargets < 1) {
        throw new IllegalArgumentException("distinctTargets must be >= 1");
      }
      if (attempts < distinctTargets) {
        throw new IllegalArgumentException(
            "attempts must be >= distinctTargets");
      }
    }
  }

  /**
   * The KDF execution limiter shed an inbound verification.
   */
  record KdfLimiterRejection() implements CredentialMetricEvent {
    public static final KdfLimiterRejection INSTANCE = new KdfLimiterRejection();
  }
}
