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

import java.util.List;

/**
 * Persistence-neutral storage of historical password verifiers.
 *
 * <p>Implementations <strong>must</strong> bound the size per user
 * — see {@link #appendAndTrim(String, PasswordHistoryEntry, int)}.
 * Unbounded history risks an attacker-controlled growth vector
 * (CWE-400).</p>
 */
public interface PasswordHistoryStore {

  /**
   * Returns the {@code max} most recent entries for {@code username},
   * newest first. An unknown user yields an empty list.
   */
  List<PasswordHistoryEntry> recent(String username, int max);

  /**
   * Appends {@code entry} and trims the per-user history to the
   * supplied retention size — the two operations run as a single
   * unit so concurrent inserts cannot bypass the cap.
   */
  void appendAndTrim(String username, PasswordHistoryEntry entry, int retainLast);
}
