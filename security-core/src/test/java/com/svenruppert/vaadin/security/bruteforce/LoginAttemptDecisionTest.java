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
package com.svenruppert.vaadin.security.bruteforce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptDecisionTest {

  @Test
  @DisplayName("allowed() returns the singleton Allowed instance")
  void allowedSingleton() {
    LoginAttemptDecision.Allowed a = LoginAttemptDecision.allowed();
    assertSame(LoginAttemptDecision.Allowed.INSTANCE, a);
    assertSame(a, LoginAttemptDecision.allowed());
  }

  @Test
  @DisplayName("lockedOut(...) carries remaining duration and failure count")
  void lockedOutCarriesPayload() {
    LoginAttemptDecision.LockedOut decision =
        LoginAttemptDecision.lockedOut(Duration.ofSeconds(120), 7);

    assertEquals(Duration.ofSeconds(120), decision.remaining());
    assertEquals(7, decision.failedAttempts());
  }

  @Test
  @DisplayName("LockedOut rejects null remaining")
  void lockedOutRejectsNullRemaining() {
    assertThrows(NullPointerException.class,
        () -> new LoginAttemptDecision.LockedOut(null, 1));
  }

  @Test
  @DisplayName("LockedOut rejects negative remaining")
  void lockedOutRejectsNegativeRemaining() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptDecision.LockedOut(Duration.ofSeconds(-1), 1));
  }

  @Test
  @DisplayName("LockedOut rejects negative failedAttempts")
  void lockedOutRejectsNegativeFailedAttempts() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptDecision.LockedOut(Duration.ofSeconds(60), -1));
  }

  @Test
  @DisplayName("LockedOut accepts zero remaining (lockout has just expired)")
  void lockedOutAcceptsZeroRemaining() {
    LoginAttemptDecision.LockedOut decision =
        LoginAttemptDecision.lockedOut(Duration.ZERO, 0);
    assertEquals(Duration.ZERO, decision.remaining());
    assertEquals(0, decision.failedAttempts());
  }

  @Test
  @DisplayName("sealed switch covers both variants exhaustively")
  void exhaustiveSwitch() {
    LoginAttemptDecision[] decisions = {
        LoginAttemptDecision.allowed(),
        LoginAttemptDecision.lockedOut(Duration.ofSeconds(30), 5)
    };

    for (LoginAttemptDecision d : decisions) {
      String label = switch (d) {
        case LoginAttemptDecision.Allowed() -> "allowed";
        case LoginAttemptDecision.LockedOut(Duration r, int n) -> "locked:" + r + ":" + n;
      };
      assertNotNull(label);
      assertFalse(label.isEmpty());
    }
  }

  @Test
  @DisplayName("LoginAttemptContext.now() supplies a timestamp around the current instant")
  void contextNow() {
    Instant before = Instant.now();
    LoginAttemptContext ctx = LoginAttemptContext.now("alice", "127.0.0.1", null);
    Instant after = Instant.now();

    assertEquals("alice", ctx.username());
    assertEquals("127.0.0.1", ctx.clientAddress());
    assertNull(ctx.sessionId());
    assertTrue(!ctx.timestamp().isBefore(before));
    assertTrue(!ctx.timestamp().isAfter(after));
  }

  @Test
  @DisplayName("LoginAttemptContext rejects null timestamp")
  void contextRejectsNullTimestamp() {
    assertThrows(NullPointerException.class,
        () -> new LoginAttemptContext("alice", "127.0.0.1", null, null));
  }

  @Test
  @DisplayName("Type witnesses for both variants are mutually exclusive")
  void typeWitnesses() {
    LoginAttemptDecision allowed = LoginAttemptDecision.allowed();
    LoginAttemptDecision locked = LoginAttemptDecision.lockedOut(Duration.ofMinutes(1), 3);

    assertInstanceOf(LoginAttemptDecision.Allowed.class, allowed);
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, locked);
    assertFalse(allowed instanceof LoginAttemptDecision.LockedOut);
    assertFalse(locked instanceof LoginAttemptDecision.Allowed);
  }
}
