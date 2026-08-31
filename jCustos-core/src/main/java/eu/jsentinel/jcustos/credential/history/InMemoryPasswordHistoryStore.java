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
package eu.jsentinel.jcustos.credential.history;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryPasswordHistoryStore implements PasswordHistoryStore {

  private final ConcurrentHashMap<String, Deque<PasswordHistoryEntry>> records =
      new ConcurrentHashMap<>();

  @Override
  public List<PasswordHistoryEntry> recent(String username, int max) {
    Objects.requireNonNull(username, "username");
    if (max < 0) {
      throw new IllegalArgumentException("max must be >= 0");
    }
    Deque<PasswordHistoryEntry> deque = records.get(username);
    if (deque == null) {
      return List.of();
    }
    synchronized (deque) {
      List<PasswordHistoryEntry> out = new ArrayList<>(Math.min(max, deque.size()));
      int taken = 0;
      var iterator = deque.descendingIterator();
      while (iterator.hasNext() && taken < max) {
        out.add(iterator.next());
        taken++;
      }
      return List.copyOf(out);
    }
  }

  @Override
  public void appendAndTrim(
      String username, PasswordHistoryEntry entry, int retainLast) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(entry, "entry");
    if (retainLast < 1) {
      throw new IllegalArgumentException("retainLast must be >= 1");
    }
    Deque<PasswordHistoryEntry> deque = records.computeIfAbsent(
        username, k -> new ArrayDeque<>());
    synchronized (deque) {
      deque.addLast(entry);
      while (deque.size() > retainLast) {
        deque.pollFirst();
      }
    }
  }

  /** Test helper: number of users with at least one entry. */
  public int trackedUsers() {
    return records.size();
  }

  /** Test helper: size of one user's history. */
  public int size(String username) {
    Objects.requireNonNull(username, "username");
    Deque<PasswordHistoryEntry> deque = records.get(username);
    if (deque == null) {
      return 0;
    }
    synchronized (deque) {
      return deque.size();
    }
  }
}
