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
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Adapter-neutral notification payload handed to a
 * {@link JCustosNotificationSender}.
 * <p>
 * Sealed by {@link Kind} — each lifecycle service emits exactly one
 * kind so a recipient (mail-provider adapter, SMS gateway, audit
 * mirror) can dispatch with a single {@code switch}. The
 * {@link #attributes()} map carries kind-specific metadata that
 * doesn't fit on the record (e.g. the plain reset-link URL, the
 * email address being verified) — the framework places stable keys
 * there and the sender is free to consume them by string.
 *
 * <p>Stable attribute keys (placed by the framework):
 * <ul>
 *   <li>{@code "tokenPlain"} — the plain token value (never the
 *       hash) for {@link Kind#PASSWORD_RESET_REQUESTED} and
 *       {@link Kind#EMAIL_VERIFICATION_REQUESTED}.</li>
 *   <li>{@code "email"} — the email address being verified for
 *       {@link Kind#EMAIL_VERIFICATION_REQUESTED} and
 *       {@link Kind#EMAIL_VERIFIED}.</li>
 *   <li>{@code "expiresAt"} — ISO-8601 string for
 *       {@code REQUESTED} kinds.</li>
 * </ul>
 *
 * @param kind       notification category; non-null
 * @param subjectId  recipient subject; non-null
 * @param tenant     tenant scope; {@code null} becomes
 *                   {@link TenantId#DEFAULT}
 * @param timestamp  emit instant; non-null
 * @param attributes immutable kind-specific metadata; null becomes
 *                   {@link Map#of()}
 */
@ExperimentalJCustosApi
public record JCustosNotification(
    Kind kind,
    SubjectId subjectId,
    TenantId tenant,
    Instant timestamp,
    Map<String, String> attributes
) {

  /** Notification category — one per lifecycle hook. */
  public enum Kind {
    /** A password-reset token was issued; deliver the plain token. */
    PASSWORD_RESET_REQUESTED,
    /** A password-reset token was consumed; confirm the change. */
    PASSWORD_RESET_COMPLETED,
    /** An email-verification token was issued; deliver the plain token. */
    EMAIL_VERIFICATION_REQUESTED,
    /** An email-verification token was consumed; confirm the verification. */
    EMAIL_VERIFIED
  }

  /** Validates the record components and freezes the attribute map. */
  public JCustosNotification {
    requireNonNull(kind, "kind must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(timestamp, "timestamp must not be null");
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }
}
