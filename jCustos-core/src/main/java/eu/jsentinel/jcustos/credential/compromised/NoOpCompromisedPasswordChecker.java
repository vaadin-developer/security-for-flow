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
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;

/**
 * Default {@link CompromisedPasswordChecker} for deployments that
 * deliberately operate without external breach data.
 *
 * <p>Every call returns {@link CompromisedPasswordResult.Clean}.
 * This is the sovereign default — the core stays usable in
 * air-gapped environments, and operators must opt in to the local
 * blocklist or the optional HIBP module if they want stricter
 * behaviour.</p>
 */
public final class NoOpCompromisedPasswordChecker
    implements CompromisedPasswordChecker {

  public static final NoOpCompromisedPasswordChecker INSTANCE =
      new NoOpCompromisedPasswordChecker();

  private NoOpCompromisedPasswordChecker() {
  }

  @Override
  public CompromisedPasswordResult check(SecretValue password) {
    return CompromisedPasswordResult.Clean.INSTANCE;
  }
}
