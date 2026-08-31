/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Adapter-neutral user / application context consumed by the
 * {@link ContextAwarePasswordValidator}.
 *
 * <p>The Konzept §14 mandates context-specific checks (CWE-521) but
 * deliberately stays away from outdated composition rules (no
 * "must contain a symbol" by default). Operators provide their own
 * forbidden-term list via {@link #forbiddenTerms()} — typically the
 * application name, the brand and any well-known buzzwords.</p>
 *
 * <p>Email addresses are split into local part and domain so the
 * validator can flag each independently. None of the fields appear
 * in {@link #toString()} verbatim beyond what {@code String.toString}
 * already produces — the values are non-secret operational metadata,
 * not credentials.</p>
 *
 * @param username        the account login; never {@code null}
 * @param emailLocalPart  optional — used for the local-part check
 * @param emailDomain     optional — used for the domain check
 * @param tenant          {@link TenantId#DEFAULT} for single-tenant
 * @param forbiddenTerms  case-insensitive substrings rejected by the
 *                        validator; defensively copied
 */
public record PasswordContext(
    String username,
    Optional<String> emailLocalPart,
    Optional<String> emailDomain,
    TenantId tenant,
    Set<String> forbiddenTerms
) {

  public PasswordContext {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    Objects.requireNonNull(emailLocalPart, "emailLocalPart");
    Objects.requireNonNull(emailDomain, "emailDomain");
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(forbiddenTerms, "forbiddenTerms");
    forbiddenTerms = Collections.unmodifiableSet(
        new LinkedHashSet<>(forbiddenTerms));
  }

  /**
   * Convenience: build a context from username plus the literal
   * {@code "local@domain"} email string. Splits on the first '@';
   * passes through empty if either half is blank.
   */
  public static PasswordContext fromEmail(
      String username, String emailAddress,
      TenantId tenant, Set<String> forbiddenTerms) {
    Optional<String> local;
    Optional<String> domain;
    if (emailAddress == null || emailAddress.isBlank()) {
      local = Optional.empty();
      domain = Optional.empty();
    } else {
      int at = emailAddress.indexOf('@');
      if (at <= 0 || at == emailAddress.length() - 1) {
        local = Optional.empty();
        domain = Optional.empty();
      } else {
        local = Optional.of(emailAddress.substring(0, at));
        domain = Optional.of(emailAddress.substring(at + 1));
      }
    }
    return new PasswordContext(
        username, local, domain,
        tenant == null ? TenantId.DEFAULT : tenant,
        forbiddenTerms == null ? Set.of() : forbiddenTerms);
  }
}
