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

import java.util.Objects;

/**
 * Strongly-typed wrapper around the application's stable subject
 * identifier.
 * <p>
 * Used at API boundaries where the alternative — a raw {@code String} —
 * would be ambiguous (a {@code logout(String)} call could plausibly mean
 * a username, a token, a session id, an opaque audit id; a
 * {@code logout(SubjectId)} call cannot).
 *
 * @param value the subject identifier as exposed by the application's
 *              {@link eu.jsentinel.jcustos.authorization.api.JCustosSubject#subjectId() JCustosSubject}.
 *              Non-{@code null}, non-blank.
 */
public record SubjectId(String value) {

  public SubjectId {
    Objects.requireNonNull(value, "value must not be null");
    if (value.isBlank()) {
      throw new IllegalArgumentException("SubjectId must not be blank");
    }
  }

  /** Convenience factory. */
  public static SubjectId of(String value) {
    return new SubjectId(value);
  }
}
