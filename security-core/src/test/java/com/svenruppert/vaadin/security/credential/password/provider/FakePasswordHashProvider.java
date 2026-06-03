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
package com.svenruppert.vaadin.security.credential.password.provider;

import com.svenruppert.vaadin.security.credential.CredentialType;
import com.svenruppert.vaadin.security.credential.InternalAuditEventType;
import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.ProviderVerificationResult;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashFormatVersion;
import com.svenruppert.vaadin.security.credential.password.pepper.PepperReference;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Deterministic, non-cryptographic provider for unit tests of the
 * registry and pipeline. Treats the password as its own "hash" so tests
 * can assert verification outcomes without spinning up a real KDF.
 *
 * <p>This is not a mock &mdash; it is a real {@link PasswordHashProvider}
 * implementation that is safe to register with the registry as long as
 * it stays under {@code src/test}.</p>
 */
public final class FakePasswordHashProvider implements PasswordHashProvider {

  public static final String PROVIDER_ID = "fake-test";
  public static final String ALGORITHM = "FakeIdentity";

  @Override
  public String providerId() {
    return PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return ALGORITHM;
  }

  @Override
  public PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<PepperReference> pepper) {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("len", Integer.toString(password.length));
    String inner = new String(password);
    return new PasswordHashResult(
        encode(inner),
        CredentialType.PASSWORD,
        PasswordHashFormatVersion.CURRENT.wireValue(),
        ALGORITHM,
        PROVIDER_ID,
        policy.policyVersion(),
        Optional.empty(),
        params
    );
  }

  @Override
  public ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<PepperReference> pepper) {
    String stored = envelope.innerHash();
    String candidate = new String(password);
    return stored.equals(candidate)
        ? ProviderVerificationResult.Matched.INSTANCE
        : ProviderVerificationResult.NotMatched.INSTANCE;
  }

  private static String encode(String raw) {
    return java.util.Base64.getEncoder().encodeToString(raw.getBytes());
  }

  /**
   * Static helper used by tests that want to construct a
   * {@link ProviderVerificationResult.ProviderError} without coupling
   * to a real provider's error path.
   */
  public static ProviderVerificationResult providerError(String message) {
    return new ProviderVerificationResult.ProviderError(
        InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
        message);
  }
}
