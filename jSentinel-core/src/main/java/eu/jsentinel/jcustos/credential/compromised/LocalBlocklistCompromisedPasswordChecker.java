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
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Offline {@link CompromisedPasswordChecker} backed by an operator-
 * supplied blocklist.
 *
 * <p>The list is normalised at construction time (case-folded, trimmed)
 * and held in a {@link Set} of strings. The blocklist exists only in
 * memory — never logged, never serialised. Lookup is case-insensitive
 * to match the NIST guidance that case variants of a known-bad
 * password are themselves bad.</p>
 *
 * <p>This implementation copies the candidate password into a temporary
 * lower-cased {@link String} for the {@link Set#contains} call and
 * does not retain it. Callers that consider this trade-off
 * unacceptable can wrap with their own hash-only blocklist.</p>
 */
public final class LocalBlocklistCompromisedPasswordChecker
    implements CompromisedPasswordChecker {

  private final Set<String> blocklist;

  /**
   * @param entries blocklist entries; each is trimmed and lower-cased.
   *                Blank entries are skipped.
   */
  public LocalBlocklistCompromisedPasswordChecker(Collection<String> entries) {
    Objects.requireNonNull(entries, "entries");
    this.blocklist = entries.stream()
        .filter(Objects::nonNull)
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .map(s -> s.toLowerCase(Locale.ROOT))
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  /** Defensive copy of the underlying set — never the live reference. */
  int size() {
    return blocklist.size();
  }

  @Override
  public CompromisedPasswordResult check(SecretValue password) {
    Objects.requireNonNull(password, "password");
    char[] chars = password.asChars();
    try {
      String candidate = new String(chars).toLowerCase(Locale.ROOT);
      try {
        if (blocklist.contains(candidate)) {
          return new CompromisedPasswordResult.Pwned(1L);
        }
        return CompromisedPasswordResult.Clean.INSTANCE;
      } finally {
        // best-effort zeroing of the lower-cased string's char[] is
        // impossible — String is immutable. The original char[] is
        // wiped below, which is the boundary we actually control.
        candidate = null;
      }
    } finally {
      Arrays.fill(chars, '\0');
    }
  }
}
