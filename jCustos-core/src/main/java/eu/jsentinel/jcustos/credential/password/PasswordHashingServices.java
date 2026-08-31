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
package eu.jsentinel.jcustos.credential.password;

import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;

import java.util.List;

/**
 * Wiring helpers for the Phase-1a {@link PasswordHashingService}.
 *
 * <p>Use {@link #defaults()} for production code that wants the safe
 * out-of-the-box configuration (OWASP-2023 PBKDF2 baseline, no pepper,
 * KDF limiter with the
 * {@link KdfResourceBudget#defaults() default budget}). Tests that need
 * tighter parameters or different limiter behaviour build the service
 * directly through the {@link DefaultPasswordHashingService} constructor.</p>
 */
public final class PasswordHashingServices {

  private PasswordHashingServices() { }

  /**
   * Builds a fully wired Phase-1a {@link PasswordHashingService} from
   * the JDK-only PBKDF2 provider, the reference policy, the no-op
   * pepper service and a semaphore-backed KDF limiter using the default
   * budget.
   */
  public static PasswordHashingService defaults() {
    return defaults(Pbkdf2Defaults.referencePolicy());
  }

  /**
   * Builds a fully wired Phase-1a {@link PasswordHashingService} that
   * follows the supplied policy. The policy must list
   * {@code PBKDF2WithHmacSHA256} / {@code pbkdf2-jdk} as the preferred
   * algorithm and provider (Phase 1a ships only the JDK provider).
   */
  public static PasswordHashingService defaults(PasswordHashPolicy policy) {
    return defaults(policy,
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()));
  }

  /**
   * Builds a fully wired Phase-1a {@link PasswordHashingService} with a
   * caller-supplied policy and KDF limiter. Mostly useful for tests
   * that want a {@code NoLimitKdfExecutionLimiter} or a tight budget.
   */
  public static PasswordHashingService defaults(
      PasswordHashPolicy policy, KdfExecutionLimiter limiter) {
    return defaults(policy, limiter, NoOpPepperService.INSTANCE);
  }

  /**
   * Builds a fully wired Phase-1a {@link PasswordHashingService} with a
   * caller-supplied policy, KDF limiter and {@link PepperService}.
   *
   * <p>Pass an {@link eu.jsentinel.jcustos.credential.password.pepper.InMemoryPepperService}
   * (or any production-grade implementation) to enable post-KDF HMAC
   * peppering. {@link NoOpPepperService#INSTANCE} disables peppering
   * altogether — equivalent to the older two-argument overload.</p>
   */
  public static PasswordHashingService defaults(
      PasswordHashPolicy policy,
      KdfExecutionLimiter limiter,
      PepperService pepperService) {
    PasswordHashProviderRegistry providerRegistry =
        new PasswordHashProviderRegistry(List.of(new Pbkdf2PasswordHashProvider()));
    if (providerRegistry.resolve(
        policy.preferredProviderId(), policy.preferredAlgorithm()).isEmpty()) {
      throw new IllegalStateException(
          "policy's preferred provider is not registered: "
              + policy.preferredProviderId() + " / "
              + policy.preferredAlgorithm());
    }
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(
            new PasswordHashParameterValidatorRegistry(List.of(
                new Pbkdf2ParameterValidator()))),
        providerRegistry,
        pepperService,
        policy,
        new RehashDecisionEngine(),
        limiter,
        new DefaultDummyVerificationService(
            providerRegistry, policy, PasswordHashCodec.DEFAULT));
  }
}
