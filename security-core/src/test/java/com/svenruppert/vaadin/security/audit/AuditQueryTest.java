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

import com.svenruppert.vaadin.security.logout.LogoutScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditQuery")
class AuditQueryTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("all() matches every event")
  void allMatchesEverything() {
    AuditQuery query = AuditQuery.all();
    assertTrue(query.matches(new LoginSucceeded(T0, "alice", null, null)));
    assertTrue(query.matches(new AccessDenied(T0, "bob", "/secret", "MissingRole")));
    assertTrue(query.matches(new BootstrapTokenRejected(T0, "Expired", null)));
  }

  @Test
  @DisplayName("ofType filters by class")
  void ofTypeFiltersByClass() {
    AuditQuery query = AuditQuery.ofType(LoginFailed.class);
    assertTrue(query.matches(new LoginFailed(T0, "alice", "127.0.0.1", "Credentials rejected")));
    assertFalse(query.matches(new LoginSucceeded(T0, "alice", null, null)));
  }

  @Test
  @DisplayName("forSubject matches subjectId on events that carry one")
  void forSubjectFiltersBySubjectId() {
    AuditQuery query = AuditQuery.forSubject("alice");
    assertTrue(query.matches(new AccessGranted(T0, "alice", "/dashboard")));
    assertTrue(query.matches(new LogoutPerformed(T0, "alice", null, LogoutScope.CurrentSession)));
    assertFalse(query.matches(new AccessGranted(T0, "bob", "/dashboard")));
  }

  @Test
  @DisplayName("forSubject treats LoginSucceeded.username as the subjectId")
  void forSubjectFallsBackToUsernameForLoginEvents() {
    AuditQuery query = AuditQuery.forSubject("alice");
    assertTrue(query.matches(new LoginSucceeded(T0, "alice", null, null)));
    assertTrue(query.matches(new LoginFailed(T0, "alice", null, "Credentials rejected")));
    assertFalse(query.matches(new LoginSucceeded(T0, "bob", null, null)));
  }

  @Test
  @DisplayName("BootstrapTokenRejected carries no subject — forSubject excludes it")
  void bootstrapTokenRejectedExcludedByForSubject() {
    AuditQuery query = AuditQuery.forSubject("alice");
    assertFalse(query.matches(new BootstrapTokenRejected(T0, "Expired", null)));
  }

  @Test
  @DisplayName("from/to bound the timestamp window inclusively")
  void timeWindowIsInclusive() {
    Instant earlier = T0.minusSeconds(60);
    Instant later = T0.plusSeconds(60);
    AuditQuery query = new AuditQuery(Set.of(), null, T0, later, 0);

    assertTrue(query.matches(new AccessGranted(T0, "alice", "/")));
    assertTrue(query.matches(new AccessGranted(later, "alice", "/")));
    assertFalse(query.matches(new AccessGranted(earlier, "alice", "/")));
    assertFalse(query.matches(new AccessGranted(later.plusSeconds(1), "alice", "/")));
  }

  @Test
  @DisplayName("limit must be non-negative")
  void limitCannotBeNegative() {
    assertThrows(IllegalArgumentException.class,
        () -> new AuditQuery(Set.of(), null, null, null, -1));
  }
}
