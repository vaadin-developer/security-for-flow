/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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
package com.svenruppert.jsentinel.credential.password.bouncycastle;

import com.svenruppert.jsentinel.credential.password.DefaultPasswordHashingService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingService;
import com.svenruppert.jsentinel.credential.password.bouncycastle.argon2.Argon2idDefaults;
import com.svenruppert.jsentinel.credential.password.bouncycastle.argon2.Argon2idParameterNames;
import com.svenruppert.jsentinel.credential.password.bouncycastle.argon2.Argon2idParameterValidator;
import com.svenruppert.jsentinel.credential.password.bouncycastle.argon2.Argon2idPasswordHashProvider;
import com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt.BcryptDefaults;
import com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt.BcryptParameterNames;
import com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt.BcryptParameterValidator;
import com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt.BcryptPasswordHashProvider;
import com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt.ScryptDefaults;
import com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt.ScryptParameterNames;
import com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt.ScryptParameterValidator;
import com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt.ScryptPasswordHashProvider;
import com.svenruppert.jsentinel.credential.password.dummy.DefaultDummyVerificationService;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.jsentinel.credential.password.limiter.KdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.limiter.KdfResourceBudget;
import com.svenruppert.jsentinel.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2Defaults;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import com.svenruppert.jsentinel.credential.password.pepper.NoOpPepperService;
import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashValidator;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashParameterValidatorRegistry;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.provider.PasswordHashProviderRegistry;
import com.svenruppert.jsentinel.credential.password.rehash.RehashDecisionEngine;

import java.util.List;

/**
 * Wiring helpers for the Phase-1b <em>modern</em> profile.
 *
 * <p>The modern profile prefers Argon2id for new hashes while still
 * accepting bcrypt, scrypt and PBKDF2 envelopes for verification. The
 * rehash engine flags non-Argon2id envelopes as
 * {@code ALGORITHM_DEPRECATED} so successful logins under the modern
 * profile transparently migrate their stored hashes (CWE-916).</p>
 *
 * <p>The profile is strictly opt-in: calling
 * {@link #modern()} requires this module to be on the classpath. The
 * core
 * {@link com.svenruppert.jsentinel.credential.password.PasswordHashingServices}
 * helper keeps emitting plain PBKDF2 envelopes.</p>
 */
public final class BouncyCastleHashingServices {

  private BouncyCastleHashingServices() { }

  /**
   * Returns a fully wired modern profile using the
   * {@link #modernPolicy() reference modern policy} and the default
   * {@link KdfResourceBudget#defaults() KDF resource budget}.
   */
  public static PasswordHashingService modern() {
    return modern(modernPolicy(),
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()));
  }

  /**
   * Returns a fully wired modern profile under the supplied policy.
   * The policy must list {@code Argon2id} / {@code argon2id-bc} as
   * preferred (so the modern profile remains the explicit operator
   * decision the Konzept calls for).
   */
  public static PasswordHashingService modern(PasswordHashPolicy policy) {
    return modern(policy,
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()));
  }

  /**
   * Returns a fully wired modern profile with a caller-supplied limiter.
   *
   * <p>All four Phase-1a/1b providers (Argon2id, bcrypt, scrypt,
   * PBKDF2-HMAC-SHA-256) are registered so that stored hashes from
   * any of these algorithms remain verifiable while new hashes are
   * produced through the preferred provider declared by {@code policy}.
   * Construction fails fast through {@link DefaultPasswordHashingService}
   * if the preferred provider does not match a registered one.</p>
   */
  public static PasswordHashingService modern(
      PasswordHashPolicy policy, KdfExecutionLimiter limiter) {
    PasswordHashProviderRegistry providerRegistry =
        new PasswordHashProviderRegistry(List.of(
            new Argon2idPasswordHashProvider(),
            new BcryptPasswordHashProvider(),
            new ScryptPasswordHashProvider(),
            new Pbkdf2PasswordHashProvider()));
    PasswordHashParameterValidatorRegistry validatorRegistry =
        new PasswordHashParameterValidatorRegistry(List.of(
            new Argon2idParameterValidator(),
            new BcryptParameterValidator(),
            new ScryptParameterValidator(),
            new Pbkdf2ParameterValidator()));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(validatorRegistry),
        providerRegistry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        limiter,
        new DefaultDummyVerificationService(
            providerRegistry, policy, PasswordHashCodec.DEFAULT));
  }

  /**
   * Reference modern policy: Argon2id preferred; bcrypt, scrypt and
   * PBKDF2 accepted for verification only (the rehash engine flags
   * each as deprecated).
   */
  public static PasswordHashPolicy modernPolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(BcryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(BcryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(ScryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(ScryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .addAcceptableProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.defaultParameters())
        .minimumParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.minimumParameters())
        .maximumParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.maximumParameters())
        .defaultParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.defaultParameters())
        .minimumParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.minimumParameters())
        .maximumParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.maximumParameters())
        .defaultParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.defaultParameters())
        .minimumParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.minimumParameters())
        .maximumParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.maximumParameters())
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .build();
  }
}
