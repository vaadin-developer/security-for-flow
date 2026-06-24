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
package com.svenruppert.jsentinel.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.jsentinel.audit.SessionExpired;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.session.SessionMetadata;
import com.svenruppert.jsentinel.session.SessionPolicy;
import com.svenruppert.jsentinel.session.SessionPolicyDecision;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Authenticated-only REST filter for endpoints that require any subject but
 * no specific permission.
 * <p>
 * Returns {@code 401} with body {@code Unauthorized} when no subject is
 * resolved or when the resolved session has exceeded its idle / absolute
 * lifetime per the configured {@link SessionPolicy}; delegates to the
 * handler otherwise. Generic and side-effect-free.
 */
public final class RestAuthenticationFilter {

  private final RestSubjectResolver subjectResolver;

  public RestAuthenticationFilter(RestSubjectResolver subjectResolver) {
    this.subjectResolver = subjectResolver;
  }

  public void requireAuthenticated(RestRequest request, RestResponse response, RestHandler handler) {
    Optional<JSentinelSubject> subject = subjectResolver.resolveSubject(request);
    if (subject.isEmpty()) {
      response.status(HttpStatus.UNAUTHORIZED.code());
      response.body("Unauthorized");
      return;
    }
    Optional<SessionMetadata> metadata = subjectResolver.resolveSessionMetadata(request);
    if (metadata.isPresent()) {
      SessionPolicy<Object> policy = JSentinelServiceResolver.sessionPolicy();
      SessionPolicyDecision decision = policy.evaluate(metadata.get());
      if (!(decision instanceof SessionPolicyDecision.Active)) {
        auditExpired(metadata.get(), subject.orElse(null), decision);
        response.status(HttpStatus.UNAUTHORIZED.code());
        response.body("Unauthorized");
        return;
      }
    }
    handler.handle(request, response);
  }

  private static void auditExpired(SessionMetadata metadata,
                                   JSentinelSubject subject,
                                   SessionPolicyDecision decision) {
    String reason = switch (decision) {
      case SessionPolicyDecision.Active ignored -> "Active";
      case SessionPolicyDecision.IdleTimeout ignored -> "IdleTimeout";
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored -> "AbsoluteLifetimeExceeded";
    };
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(new SessionExpired(
          Instant.now(Clock.systemUTC()),
          metadata.subjectId() == null ? "" : metadata.subjectId(),
          null,
          reason));
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }
}
