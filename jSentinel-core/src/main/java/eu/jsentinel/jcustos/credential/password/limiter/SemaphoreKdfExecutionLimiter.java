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

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * {@link KdfExecutionLimiter} backed by a fair {@link Semaphore}.
 */
public final class SemaphoreKdfExecutionLimiter implements KdfExecutionLimiter {

  private final Semaphore permits;
  private final KdfResourceBudget budget;

  public SemaphoreKdfExecutionLimiter(KdfResourceBudget budget) {
    this.budget = Objects.requireNonNull(budget, "budget");
    this.permits = new Semaphore(budget.maxConcurrent(), true);
  }

  @Override
  public Optional<Lease> acquire() {
    try {
      boolean acquired = permits.tryAcquire(
          budget.maxWait().toNanos(), TimeUnit.NANOSECONDS);
      if (!acquired) {
        return Optional.empty();
      }
      return Optional.of(new SemaphoreLease(permits));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Optional.empty();
    }
  }

  /**
   * Snapshot count of available permits. Exposed for tests; production
   * code must not branch on this value because it would create an
   * observable load signal.
   */
  int availablePermits() {
    return permits.availablePermits();
  }

  KdfResourceBudget budget() {
    return budget;
  }

  private static final class SemaphoreLease implements Lease {

    private final Semaphore semaphore;
    private boolean released;

    SemaphoreLease(Semaphore semaphore) {
      this.semaphore = semaphore;
    }

    @Override
    public void close() {
      if (!released) {
        released = true;
        semaphore.release();
      }
    }
  }
}
