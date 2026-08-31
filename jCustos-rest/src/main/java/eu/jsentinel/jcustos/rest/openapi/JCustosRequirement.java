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
package eu.jsentinel.jcustos.rest.openapi;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Adapter-neutral description of a single security requirement
 * extracted from a {@code @Requires…} / {@code @ProtectedBy}
 * annotation on a REST handler. Multiple requirements compose
 * with AND semantics (the operation needs every requirement to
 * pass — same model as the runtime evaluator).
 *
 * <p>The {@code values} list is interpreted relative to
 * {@code scheme} and {@code operator}:
 * <ul>
 *   <li>{@link Scheme#PERMISSION} with {@link Operator#ALL} —
 *       subject must have <em>every</em> listed permission.</li>
 *   <li>{@link Scheme#PERMISSION} with {@link Operator#ANY} —
 *       subject must have at least one.</li>
 *   <li>{@link Scheme#ROLE} with {@link Operator#ALL} — subject
 *       must have every listed role.</li>
 *   <li>{@link Scheme#POLICY} with {@link Operator#ALL} — every
 *       listed policy name must permit the request.</li>
 * </ul>
 *
 * @param scheme   what kind of authorization the requirement
 *                 describes; non-null
 * @param operator how the values combine; non-null
 * @param values   names of the required permissions / roles /
 *                 policies; non-null, non-empty, immutable
 */
@ExperimentalJCustosApi
public record JCustosRequirement(
    Scheme scheme,
    Operator operator,
    List<String> values
) {

  /** Validates the components and freezes the values list. */
  public JCustosRequirement {
    requireNonNull(scheme, "scheme must not be null");
    requireNonNull(operator, "operator must not be null");
    requireNonNull(values, "values must not be null");
    if (values.isEmpty()) {
      throw new IllegalArgumentException("values must not be empty");
    }
    for (String v : values) {
      if (v == null || v.isBlank()) {
        throw new IllegalArgumentException("values must not contain blanks");
      }
    }
    values = List.copyOf(values);
  }

  /** What the requirement is about. */
  public enum Scheme {
    PERMISSION,
    ROLE,
    POLICY
  }

  /** How the {@code values} combine. */
  public enum Operator {
    ALL,
    ANY
  }
}
