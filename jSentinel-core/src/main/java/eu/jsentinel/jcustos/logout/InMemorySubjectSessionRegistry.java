/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.logout;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory {@link SubjectSessionRegistry} suitable for single-node
 * deployments and demos.
 * <p>
 * Thread-safe via a {@link ConcurrentMap} keyed by {@link SubjectId}.
 * Each value is a synchronized {@code LinkedHashSet} so registrations
 * preserve insertion order — useful for diagnostics.
 */
public final class InMemorySubjectSessionRegistry implements SubjectSessionRegistry {

  private final ConcurrentMap<SubjectId, Set<String>> bySubject = new ConcurrentHashMap<>();

  @Override
  public void register(SubjectId subjectId, String sessionId) {
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(sessionId, "sessionId");
    bySubject.compute(subjectId, (key, current) -> {
      Set<String> updated = current == null ? newSessionSet() : current;
      updated.add(sessionId);
      return updated;
    });
  }

  @Override
  public void unregister(SubjectId subjectId, String sessionId) {
    if (subjectId == null || sessionId == null) {
      return;
    }
    bySubject.computeIfPresent(subjectId, (key, current) -> {
      current.remove(sessionId);
      return current.isEmpty() ? null : current;
    });
  }

  @Override
  public Collection<String> sessionsOf(SubjectId subjectId) {
    if (subjectId == null) {
      return List.of();
    }
    Set<String> snapshot = bySubject.get(subjectId);
    if (snapshot == null) {
      return List.of();
    }
    synchronized (snapshot) {
      return List.copyOf(snapshot);
    }
  }

  @Override
  public Collection<String> clearAll(SubjectId subjectId) {
    if (subjectId == null) {
      return List.of();
    }
    Set<String> removed = bySubject.remove(subjectId);
    if (removed == null) {
      return List.of();
    }
    synchronized (removed) {
      return List.copyOf(removed);
    }
  }

  private static Set<String> newSessionSet() {
    return java.util.Collections.synchronizedSet(new LinkedHashSet<>());
  }
}
