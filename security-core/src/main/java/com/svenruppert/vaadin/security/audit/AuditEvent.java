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
package com.svenruppert.vaadin.security.audit;

import java.time.Instant;

/**
 * Sealed root of the typed security audit event hierarchy.
 * <p>
 * Each subtype is an immutable {@code record} that carries only the fields
 * meaningful for its category — there is no shared map of free-form
 * attributes. Use pattern matching ({@code switch} on {@code AuditEvent})
 * to consume events.
 * <p>
 * Every variant carries a non-{@code null} {@link #timestamp() timestamp}
 * captured at the moment the event was created.
 *
 * @see AuditSink
 */
public sealed interface AuditEvent
    permits LoginSucceeded, LoginFailed, LogoutPerformed,
            AccessGranted, AccessDenied, ActionDenied,
            BruteForceLimitReached,
            SessionCreated, SessionExpired, SessionInvalidated, SessionStale,
            RoleAssigned, RoleRevoked,
            UserCreated, UserDeleted,
            BootstrapAdminCreated, BootstrapTokenRejected,
            PolicyEvaluated, StepUpChallenged,
            PasswordResetRequested, PasswordResetCompleted,
            EmailVerificationRequested, EmailVerified,
            ApiKeyUsed, ApiKeyDenied, TokenRotated,
            RateLimitExceeded,
            CredentialVerificationSucceeded,
            CredentialVerificationFailed,
            CredentialRehashed {

  /** The UTC instant at which this event was created. Never {@code null}. */
  Instant timestamp();
}
