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
package com.svenruppert.jsentinel.credential.password.limiter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SemaphoreKdfExecutionLimiterTest {

  @Test
  @DisplayName("Budget rejects zero or negative concurrency")
  void budgetInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new KdfResourceBudget(0, Duration.ofMillis(50)));
    assertThrows(IllegalArgumentException.class,
        () -> new KdfResourceBudget(-1, Duration.ofMillis(50)));
    assertThrows(IllegalArgumentException.class,
        () -> new KdfResourceBudget(1, Duration.ofMillis(-1)));
  }

  @Test
  @DisplayName("acquire returns a lease that releases on close")
  void acquireAndRelease() {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(2, Duration.ofMillis(50)));
    Optional<KdfExecutionLimiter.Lease> first = limiter.acquire();
    Optional<KdfExecutionLimiter.Lease> second = limiter.acquire();
    assertTrue(first.isPresent());
    assertTrue(second.isPresent());
    assertEquals(0, limiter.availablePermits());

    first.get().close();
    assertEquals(1, limiter.availablePermits());
    second.get().close();
    assertEquals(2, limiter.availablePermits());
  }

  @Test
  @DisplayName("close is idempotent")
  void closeIsIdempotent() {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    KdfExecutionLimiter.Lease lease = limiter.acquire().orElseThrow();
    lease.close();
    lease.close();
    assertEquals(1, limiter.availablePermits());
  }

  @Test
  @DisplayName("Limiter rejects beyond the configured concurrency within maxWait")
  void rejectsOnSaturation() throws InterruptedException {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50)));

    CountDownLatch acquired = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);

    Thread holder = new Thread(() -> {
      KdfExecutionLimiter.Lease l = limiter.acquire().orElseThrow();
      acquired.countDown();
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

    assertTrue(acquired.await(2, TimeUnit.SECONDS));

    long start = System.nanoTime();
    Optional<KdfExecutionLimiter.Lease> contested = limiter.acquire();
    long elapsedNanos = System.nanoTime() - start;

    assertTrue(contested.isEmpty(),
        "Second caller must be rejected when the only permit is held");
    long elapsedMillis = elapsedNanos / 1_000_000L;
    assertTrue(elapsedMillis >= 40L,
        "Rejection must respect the bounded wait (got " + elapsedMillis + "ms)");
    assertTrue(elapsedMillis < 1000L,
        "Rejection must not block forever (got " + elapsedMillis + "ms)");

    release.countDown();
    holder.join(1000);
  }

  @Test
  @DisplayName("NoLimit limiter never rejects")
  void noLimitNeverRejects() {
    assertNotNull(NoLimitKdfExecutionLimiter.INSTANCE.acquire().orElseThrow());
  }
}
