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
package com.svenruppert.vaadin.security.credential.reset;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryResetTokenStore implements ResetTokenStore {

  private final ConcurrentHashMap<String, ResetTokenRecord> records =
      new ConcurrentHashMap<>();

  @Override
  public void save(ResetTokenRecord record) {
    Objects.requireNonNull(record, "record");
    ResetTokenRecord prior = records.putIfAbsent(record.selector(), record);
    if (prior != null) {
      throw new IllegalStateException(
          "reset token already exists for selector");
    }
  }

  @Override
  public Optional<ResetTokenRecord> findBySelector(String selector) {
    Objects.requireNonNull(selector, "selector");
    return Optional.ofNullable(records.get(selector));
  }

  @Override
  public ResetTokenUpdateResult markConsumedIfCurrent(
      String selector, ResetTokenStatus expectedStatus) {
    return transition(selector, expectedStatus, ResetTokenStatus.CONSUMED);
  }

  @Override
  public ResetTokenUpdateResult markExpiredIfCurrent(
      String selector, ResetTokenStatus expectedStatus) {
    return transition(selector, expectedStatus, ResetTokenStatus.EXPIRED);
  }

  private ResetTokenUpdateResult transition(
      String selector, ResetTokenStatus expected, ResetTokenStatus target) {
    Objects.requireNonNull(selector, "selector");
    Objects.requireNonNull(expected, "expected");
    Objects.requireNonNull(target, "target");
    ResetTokenRecord current = records.get(selector);
    if (current == null) {
      return ResetTokenUpdateResult.NotFound.INSTANCE;
    }
    if (current.status() != expected) {
      return ResetTokenUpdateResult.Stale.INSTANCE;
    }
    ResetTokenRecord next = current.withStatus(target);
    if (!records.replace(selector, current, next)) {
      return ResetTokenUpdateResult.Stale.INSTANCE;
    }
    return new ResetTokenUpdateResult.Updated(next);
  }

  /** Test helper: number of stored tokens. */
  public int size() {
    return records.size();
  }
}
