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
package eu.jsentinel.jcustos.credential.password.limiter;

import java.util.Optional;

/**
 * Limiter that never blocks and never rejects. Useful for unit tests
 * and for environments where the operator decided to delegate concurrency
 * control elsewhere (e.g. a servlet container thread pool).
 */
public final class NoLimitKdfExecutionLimiter implements KdfExecutionLimiter {

  public static final NoLimitKdfExecutionLimiter INSTANCE =
      new NoLimitKdfExecutionLimiter();

  private static final Lease NOOP_LEASE = () -> { };

  @Override
  public Optional<Lease> acquire() {
    return Optional.of(NOOP_LEASE);
  }
}
