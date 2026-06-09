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
import com.svenruppert.jsentinel.credential.password.dummy.DummyVerificationContext;
import com.svenruppert.jsentinel.credential.password.dummy.DummyVerificationService;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashFormatException;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashRecord;
import com.svenruppert.jsentinel.credential.password.limiter.KdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.pepper.PepperReference;
import com.svenruppert.jsentinel.credential.password.pepper.PepperService;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashValidationException;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashValidator;
import com.svenruppert.jsentinel.credential.password.provider.PasswordHashProvider;
import com.svenruppert.jsentinel.credential.password.provider.PasswordHashProviderRegistry;
import com.svenruppert.jsentinel.credential.password.rehash.RehashDecisionEngine;

import java.util.Objects;
import java.util.Optional;

/**
 * Reference {@link PasswordHashingService}.
 *
 * <p>Each {@code verify(...)} call walks the pipeline in this strict
 * order:</p>
 *
 * <ol>
 *   <li><strong>acquire limiter permit</strong> &mdash; one
 *       {@link KdfExecutionLimiter} permit covers the whole call,
 *       including any dummy KDF taken on failure;</li>
 *   <li><strong>parse</strong> &mdash; decode the envelope through
 *       {@link PasswordHashCodec};</li>
 *   <li><strong>validate</strong> &mdash; gate the envelope through
 *       {@link PasswordHashValidator} (rejects out-of-bound parameters
 *       cheaply, CWE-400);</li>
 *   <li><strong>resolveProvider</strong> &mdash; look up the provider
 *       that produced the envelope (CWE-693);</li>
 *   <li><strong>resolvePepper</strong> &mdash; ask the
 *       {@link PepperService} for the stored pepper key; Phase 1a's
 *       {@code NoOpPepperService} never resolves a key, so any
 *       peppered envelope correctly fails verification rather than
 *       getting silently downgraded;</li>
 *   <li><strong>verify</strong> &mdash; delegate the constant-time
 *       comparison to the provider;</li>
 *   <li><strong>rehashDecision</strong> &mdash; on success, compute
 *       whether the envelope should be transparently upgraded.</li>
 * </ol>
 *
 * <p>Every failure path executes a comparable
 * {@link DummyVerificationService} call before returning so that
 * &quot;user does not exist&quot;, &quot;envelope is malformed&quot;
 * and &quot;provider is missing&quot; collapse onto the same
 * observable timing profile (CWE-203, CWE-208). Every public failure
 * collapses onto {@link PublicFailureType#INVALID_CREDENTIALS}; the
 * differentiated {@link InternalAuditEventType} is preserved for audit
 * sinks.</p>
 */
public final class DefaultPasswordHashingService implements PasswordHashingService {

  private final PasswordHashCodec codec;
  private final PasswordHashValidator validator;
  private final PasswordHashProviderRegistry providerRegistry;
  private final PepperService pepperService;
  private final PasswordHashPolicy policy;
  private final RehashDecisionEngine rehashEngine;
  private final KdfExecutionLimiter limiter;
  private final DummyVerificationService dummyService;

  public DefaultPasswordHashingService(
      PasswordHashCodec codec,
      PasswordHashValidator validator,
      PasswordHashProviderRegistry providerRegistry,
      PepperService pepperService,
      PasswordHashPolicy policy,
      RehashDecisionEngine rehashEngine,
      KdfExecutionLimiter limiter,
      DummyVerificationService dummyService) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.validator = Objects.requireNonNull(validator, "validator");
    this.providerRegistry = Objects.requireNonNull(
        providerRegistry, "providerRegistry");
    this.pepperService = Objects.requireNonNull(pepperService, "pepperService");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.rehashEngine = Objects.requireNonNull(rehashEngine, "rehashEngine");
    this.limiter = Objects.requireNonNull(limiter, "limiter");
    this.dummyService = Objects.requireNonNull(dummyService, "dummyService");

    PasswordHashProvider preferred = providerRegistry.resolve(
        policy.preferredProviderId(), policy.preferredAlgorithm())
        .orElseThrow(() -> new IllegalStateException(
            "policy's preferred provider is not registered"));
    if (!preferred.algorithm().equals(policy.preferredAlgorithm())
        || !preferred.providerId().equals(policy.preferredProviderId())) {
      throw new IllegalStateException(
          "preferred provider does not advertise the preferred algorithm");
    }
  }

  @Override
  public PasswordHashResult hash(char[] password) {
    Objects.requireNonNull(password, "password");
    PasswordHashProvider provider = providerRegistry
        .resolve(policy.preferredProviderId(), policy.preferredAlgorithm())
        .orElseThrow(() -> new IllegalStateException(
            "preferred provider disappeared after construction"));
    Optional<PepperReference> pepper = resolveActivePepper();
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      throw new KdfLimitExceededException();
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      return provider.hash(password, policy, pepper);
    }
  }

  @Override
  public CredentialVerificationResult verify(
      char[] password, String encodedHash) {
    Objects.requireNonNull(password, "password");
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      return failed(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT);
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      return verifyUnderLease(password, encodedHash);
    }
  }

  @Override
  public CredentialVerificationResult verifyAgainstNothing(char[] password) {
    Objects.requireNonNull(password, "password");
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      return failed(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT);
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      dummyService.runDummyKdf(password, DummyVerificationContext.UNKNOWN_USER);
      return failed(InternalAuditEventType.VERIFICATION_DUMMY_PATH);
    }
  }

  @Override
  public RehashDecision needsRehash(String encodedHash) {
    if (encodedHash == null) {
      return RehashDecision.NotRequired.INSTANCE;
    }
    try {
      PasswordHashRecord record = codec.decode(encodedHash);
      return rehashEngine.decide(
          record.envelope(), policy, pepperService.activeKeyId());
    } catch (PasswordHashFormatException e) {
      return RehashDecision.NotRequired.INSTANCE;
    }
  }

  private CredentialVerificationResult verifyUnderLease(
      char[] password, String encodedHash) {
    if (encodedHash == null) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_DECODE_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR);
    }

    PasswordHashRecord record;
    try {
      record = codec.decode(encodedHash);
    } catch (PasswordHashFormatException e) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_DECODE_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR);
    }

    PasswordHashEnvelope envelope = record.envelope();

    try {
      validator.validate(envelope, policy);
    } catch (PasswordHashValidationException e) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_VALIDATION_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS);
    }

    Optional<PasswordHashProvider> resolvedProvider = providerRegistry
        .resolve(envelope.providerId(), envelope.algorithm());
    if (resolvedProvider.isEmpty()) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.PROVIDER_MISSING);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER);
    }

    Optional<PepperReference> pepperReference;
    if (envelope.pepperKeyId().isPresent()) {
      String keyId = envelope.pepperKeyId().get();
      Optional<byte[]> resolved = pepperService.resolve(keyId);
      if (resolved.isEmpty()) {
        dummyService.runDummyKdf(password,
            DummyVerificationContext.PEPPER_KEY_UNKNOWN);
        return failed(
            InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY);
      }
      try {
        pepperReference = Optional.of(new PepperReference(keyId, resolved.get()));
      } catch (IllegalArgumentException e) {
        dummyService.runDummyKdf(password,
            DummyVerificationContext.PEPPER_KEY_UNKNOWN);
        return failed(
            InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY);
      } finally {
        java.util.Arrays.fill(resolved.get(), (byte) 0);
      }
    } else {
      pepperReference = Optional.empty();
    }

    ProviderVerificationResult providerResult = resolvedProvider.get()
        .verify(password, envelope, pepperReference);

    return switch (providerResult) {
      case ProviderVerificationResult.Matched ignored ->
          new CredentialVerificationResult.Verified(
              record.encoded(),
              envelope.credentialType(),
              envelope.algorithm(),
              envelope.providerId(),
              envelope.formatVersion().wireValue(),
              envelope.policyVersion(),
              envelope.pepperKeyId());
      case ProviderVerificationResult.NotMatched ignored ->
          failed(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH);
      case ProviderVerificationResult.ProviderError err ->
          failed(err.internalAuditEventType());
    };
  }

  private static CredentialVerificationResult.Failed failed(
      InternalAuditEventType internal) {
    return new CredentialVerificationResult.Failed(
        PublicFailureType.INVALID_CREDENTIALS, internal);
  }

  private Optional<PepperReference> resolveActivePepper() {
    Optional<String> activeKey = pepperService.activeKeyId();
    if (activeKey.isEmpty()) {
      return Optional.empty();
    }
    Optional<byte[]> resolved = pepperService.resolve(activeKey.get());
    if (resolved.isEmpty()) {
      throw new IllegalStateException(
          "active pepper key id does not resolve in the pepper service");
    }
    byte[] keyBytes = resolved.get();
    try {
      return Optional.of(new PepperReference(activeKey.get(), keyBytes));
    } finally {
      java.util.Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Thrown by {@link #hash(char[])} when the limiter is saturated.
   * Verification paths translate this into a generic credential failure
   * instead of throwing.
   */
  public static final class KdfLimitExceededException extends RuntimeException {
    public KdfLimitExceededException() {
      super("KDF execution limiter rejected the request");
    }
  }
}
