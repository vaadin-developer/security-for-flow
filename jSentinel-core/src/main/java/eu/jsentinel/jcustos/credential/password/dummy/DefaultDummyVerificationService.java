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
package eu.jsentinel.jcustos.credential.password.dummy;

import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;

import java.util.Objects;
import java.util.Optional;

/**
 * Reference {@link DummyVerificationService}.
 *
 * <p>Caches a single envelope built under the active policy at
 * construction time (against a fixed, well-known &quot;dummy&quot;
 * password) and verifies the supplied candidate against that envelope
 * on every call.</p>
 *
 * <p>If the policy's preferred provider is somehow unavailable at call
 * time, the service falls back to whichever provider is registered for
 * the preferred algorithm, then to the first registered provider. The
 * dummy path therefore always performs <em>some</em> KDF work, never
 * short-circuits, and never throws.</p>
 */
public final class DefaultDummyVerificationService implements DummyVerificationService {

  private static final char[] DUMMY_PASSWORD = "00.71.00-dummy-credential".toCharArray();

  private final PasswordHashProviderRegistry providerRegistry;
  private final PasswordHashPolicy policy;
  private final PasswordHashEnvelope cachedEnvelope;

  public DefaultDummyVerificationService(
      PasswordHashProviderRegistry providerRegistry,
      PasswordHashPolicy policy,
      PasswordHashCodec codec) {
    this.providerRegistry = Objects.requireNonNull(
        providerRegistry, "providerRegistry");
    this.policy = Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(codec, "codec");

    PasswordHashProvider provider = resolveAnyProvider()
        .orElseThrow(() -> new IllegalStateException(
            "no password hash provider available to build the dummy envelope"));
    PasswordHashResult dummy = provider.hash(
        DUMMY_PASSWORD.clone(), policy, Optional.empty());
    this.cachedEnvelope = codec.decode(dummy.encodedHash()).envelope();
  }

  @Override
  public void runDummyKdf(char[] password, DummyVerificationContext context) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(context, "context");
    PasswordHashProvider provider = resolveAnyProvider().orElse(null);
    if (provider == null) {
      return;
    }
    // Use the cached envelope so we exercise a real KDF run. The result
    // is intentionally discarded; the only purpose of this call is to
    // consume comparable CPU/memory and to pressure the KDF limiter.
    provider.verify(password, cachedEnvelope, Optional.empty());
  }

  private Optional<PasswordHashProvider> resolveAnyProvider() {
    Optional<PasswordHashProvider> preferred = providerRegistry.resolve(
        policy.preferredProviderId(), policy.preferredAlgorithm());
    if (preferred.isPresent()) {
      return preferred;
    }
    for (PasswordHashProvider p : providerRegistry.providers()) {
      if (p.algorithm().equals(policy.preferredAlgorithm())) {
        return Optional.of(p);
      }
    }
    return providerRegistry.providers().stream().findFirst();
  }
}
