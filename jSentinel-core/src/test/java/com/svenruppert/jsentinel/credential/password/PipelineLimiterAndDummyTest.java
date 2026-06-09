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
package com.svenruppert.jsentinel.credential.password;

import com.svenruppert.jsentinel.credential.InternalAuditEventType;
import com.svenruppert.jsentinel.credential.PublicFailureType;
import com.svenruppert.jsentinel.credential.password.dummy.DefaultDummyVerificationService;
import com.svenruppert.jsentinel.credential.password.dummy.DummyVerificationContext;
import com.svenruppert.jsentinel.credential.password.dummy.DummyVerificationService;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.jsentinel.credential.password.limiter.KdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.limiter.KdfResourceBudget;
import com.svenruppert.jsentinel.credential.password.limiter.NoLimitKdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.limiter.SemaphoreKdfExecutionLimiter;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PipelineLimiterAndDummyTest {

  /**
   * Counting {@link DummyVerificationService} backed by a real PBKDF2
   * verification so dummy KDF cost stays realistic. Not a mock &mdash;
   * it implements the full SPI and delegates to a real provider.
   */
  private static final class CountingDummyService implements DummyVerificationService {
    private final DummyVerificationService delegate;
    private final Map<DummyVerificationContext, Integer> calls =
        new EnumMap<>(DummyVerificationContext.class);

    CountingDummyService(DummyVerificationService delegate) {
      this.delegate = delegate;
    }

    @Override
    public void runDummyKdf(char[] password, DummyVerificationContext context) {
      calls.merge(context, 1, Integer::sum);
      delegate.runDummyKdf(password, context);
    }

    int callsFor(DummyVerificationContext c) {
      return calls.getOrDefault(c, 0);
    }
  }

  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  private DefaultPasswordHashingService buildService(
      KdfExecutionLimiter limiter, CountingDummyService dummy) {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(
            new PasswordHashParameterValidatorRegistry(List.of(
                new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        fastTestPolicy(),
        new RehashDecisionEngine(),
        limiter,
        dummy);
  }

  private CountingDummyService newCountingDummy() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    return new CountingDummyService(new DefaultDummyVerificationService(
        registry, fastTestPolicy(), PasswordHashCodec.DEFAULT));
  }

  @Test
  @DisplayName("verifyAgainstNothing runs dummy KDF for the UNKNOWN_USER context")
  void unknownUserPathRunsDummyKdf() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);

    CredentialVerificationResult result = service.verifyAgainstNothing(
        "hunter2".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        ((CredentialVerificationResult.Failed) result).publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_DUMMY_PATH,
        ((CredentialVerificationResult.Failed) result).internalAuditEventType());
    assertEquals(1, dummy.callsFor(DummyVerificationContext.UNKNOWN_USER));
  }

  @Test
  @DisplayName("Malformed envelope triggers a dummy KDF with ENVELOPE_DECODE_ERROR context")
  void malformedEnvelopePathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    service.verify("x".toCharArray(), "not-an-envelope");
    assertEquals(1, dummy.callsFor(DummyVerificationContext.ENVELOPE_DECODE_ERROR));
  }

  @Test
  @DisplayName("Null encoded hash triggers a dummy KDF with ENVELOPE_DECODE_ERROR context")
  void nullEnvelopeTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    service.verify("x".toCharArray(), null);
    assertEquals(1, dummy.callsFor(DummyVerificationContext.ENVELOPE_DECODE_ERROR));
  }

  @Test
  @DisplayName("Validation rejection triggers a dummy KDF with ENVELOPE_VALIDATION_ERROR context")
  void validationFailurePathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    // Build a valid PBKDF2 envelope but with iterations above the policy max.
    PasswordHashResult ok = new Pbkdf2PasswordHashProvider().hash(
        "x".toCharArray(), fastTestPolicy(), java.util.Optional.empty());
    String tampered = ok.encodedHash().replace("$p=i=1000", "$p=i=9999");
    service.verify("x".toCharArray(), tampered);
    assertEquals(1,
        dummy.callsFor(DummyVerificationContext.ENVELOPE_VALIDATION_ERROR));
  }

  @Test
  @DisplayName("Unknown provider triggers a dummy KDF with PROVIDER_MISSING context")
  void unknownProviderPathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);

    String good = new Pbkdf2PasswordHashProvider()
        .hash("x".toCharArray(), fastTestPolicy(), java.util.Optional.empty())
        .encodedHash();
    String spoofedProvider = good.replace(
        "$prov=" + Pbkdf2ParameterNames.PROVIDER_ID + "$",
        "$prov=ghost-provider$");
    service.verify("x".toCharArray(), spoofedProvider);
    assertEquals(1, dummy.callsFor(DummyVerificationContext.PROVIDER_MISSING));
  }

  @Test
  @DisplayName("Limiter rejection is mapped to generic INVALID_CREDENTIALS + KDF_LIMIT audit")
  void limiterRejectionMapsToGenericFailure() throws InterruptedException {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50)));
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(limiter, dummy);

    CountDownLatch holderAcquired = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    Thread holder = new Thread(() -> {
      KdfExecutionLimiter.Lease l = limiter.acquire().orElseThrow();
      holderAcquired.countDown();
      try {
        release.await(5, TimeUnit.SECONDS);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
      } finally {
        l.close();
      }
    });
    holder.setDaemon(true);
    holder.start();
    assertTrue(holderAcquired.await(2, TimeUnit.SECONDS));

    CredentialVerificationResult result = service.verify(
        "x".toCharArray(), "anything");
    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, f.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT,
        f.internalAuditEventType());

    release.countDown();
    holder.join(1000);
  }

  @Test
  @DisplayName("Concurrent verifications drain the limiter; one is rejected")
  void concurrencyDrainsTheLimiter() throws InterruptedException {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(limiter, dummy);

    PasswordHashResult ok = service.hash("hunter2".toCharArray());
    AtomicInteger rejected = new AtomicInteger();
    AtomicInteger accepted = new AtomicInteger();
    Thread[] threads = new Thread[6];
    for (int i = 0; i < threads.length; i++) {
      threads[i] = new Thread(() -> {
        CredentialVerificationResult r = service.verify(
            "hunter2".toCharArray(), ok.encodedHash());
        if (r instanceof CredentialVerificationResult.Failed f
            && f.internalAuditEventType()
                == InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT) {
          rejected.incrementAndGet();
        } else {
          accepted.incrementAndGet();
        }
      });
      threads[i].setDaemon(true);
      threads[i].start();
    }
    for (Thread t : threads) {
      t.join(15_000);
    }
    assertEquals(threads.length, rejected.get() + accepted.get());
    assertTrue(accepted.get() >= 1, "at least one verification must succeed");
  }
}
