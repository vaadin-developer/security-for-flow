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
package com.svenruppert.vaadin.security.authentication;

import com.svenruppert.vaadin.security.audit.ApiKeyDenied;
import com.svenruppert.vaadin.security.audit.ApiKeyUsed;
import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ApiKeyAuthenticationService")
class ApiKeyAuthenticationServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final PermissionName READ = new PermissionName("document:read");

  private static final class FakeHasher implements PasswordHasher {
    @Override public String hash(char[] raw) {
      return "h:" + HexFormat.of().formatHex(new String(raw).getBytes());
    }
    @Override public boolean verify(char[] raw, String stored) {
      return hash(raw).equals(stored);
    }
  }

  private static Clock fixed(Instant at) { return Clock.fixed(at, ZoneOffset.UTC); }

  private ApiKeyRecord seed(InMemoryApiKeyStore store, FakeHasher hasher,
                            String plain, String name) {
    ApiKeyRecord record = new ApiKeyRecord(
        hasher.hash(plain.toCharArray()), TenantId.DEFAULT, ALICE,
        name, Set.of(READ), T0,
        Optional.of(T0.plusSeconds(3600)),
        Optional.empty(), Optional.empty());
    store.save(record);
    return record;
  }

  @Test
  @DisplayName("authenticate on a live key returns the record and emits ApiKeyUsed")
  void authenticateLiveKey() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyRecord record = seed(store, hasher, "plain-k1", "my-key");

    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, hasher, audit, TenantId.DEFAULT, fixed(T0.plusSeconds(60)));

    Optional<ApiKeyRecord> authed = service.authenticate("plain-k1");
    assertTrue(authed.isPresent());
    assertEquals(record.keyHash(), authed.get().keyHash());
    assertEquals(Optional.of(T0.plusSeconds(60)), authed.get().lastUsedAt());

    // store updated
    assertEquals(Optional.of(T0.plusSeconds(60)),
        store.findByHash(record.keyHash()).orElseThrow().lastUsedAt());

    // audit: a single ApiKeyUsed
    assertEquals(1, audit.published.size());
    ApiKeyUsed used = (ApiKeyUsed) audit.published.get(0);
    assertEquals("alice", used.subjectId());
    assertEquals("my-key", used.keyName());
    assertEquals(record.keyHash(), used.keyHash());
  }

  @Test
  @DisplayName("unknown key → empty + ApiKeyDenied{reason=Unknown}")
  void unknownKeyDenied() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, hasher, audit, TenantId.DEFAULT, fixed(T0));

    assertTrue(service.authenticate("ghost").isEmpty());

    assertEquals(1, audit.published.size());
    ApiKeyDenied denied = (ApiKeyDenied) audit.published.get(0);
    assertEquals("Unknown", denied.reason());
    assertEquals("", denied.subjectId());
  }

  @Test
  @DisplayName("foreign-tenant key → empty + ApiKeyDenied{reason=ForeignTenant}")
  void foreignTenantDenied() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    ApiKeyRecord record = new ApiKeyRecord(
        hasher.hash("plain".toCharArray()),
        new TenantId("acme"), ALICE, "k", Set.of(), T0,
        Optional.empty(), Optional.empty(), Optional.empty());
    store.save(record);

    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyAuthenticationService defaultSvc = new ApiKeyAuthenticationService(
        store, hasher, audit, TenantId.DEFAULT, fixed(T0));

    assertTrue(defaultSvc.authenticate("plain").isEmpty());
    assertEquals("ForeignTenant", ((ApiKeyDenied) audit.published.get(0)).reason());
  }

  @Test
  @DisplayName("revoked key → empty + ApiKeyDenied{reason=Revoked}")
  void revokedKeyDenied() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    ApiKeyRecord record = seed(store, hasher, "plain", "k")
        .withRevokedAt(T0.plusSeconds(10));
    store.save(record);

    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, hasher, audit, TenantId.DEFAULT, fixed(T0.plusSeconds(20)));

    assertTrue(service.authenticate("plain").isEmpty());
    assertEquals("Revoked", ((ApiKeyDenied) audit.published.get(0)).reason());
  }

  @Test
  @DisplayName("expired key → empty + ApiKeyDenied{reason=Expired}")
  void expiredKeyDenied() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    seed(store, hasher, "plain", "k"); // expires at T0+3600

    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, hasher, audit, TenantId.DEFAULT, fixed(T0.plusSeconds(7200)));

    assertTrue(service.authenticate("plain").isEmpty());
    assertEquals("Expired", ((ApiKeyDenied) audit.published.get(0)).reason());
  }

  @Test
  @DisplayName("null / blank input is silently rejected (no audit)")
  void blankInputRejected() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    CollectingAuditService audit = new CollectingAuditService();
    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, new FakeHasher(), audit);
    assertTrue(service.authenticate(null).isEmpty());
    assertTrue(service.authenticate("").isEmpty());
    assertTrue(audit.published.isEmpty(),
        "no audit for malformed input — the request is rejected before reaching the store");
  }

  @Test
  @DisplayName("audit failures do not turn success into denial")
  void auditFailureSwallowed() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    seed(store, hasher, "plain", "k");

    JSentinelAuditService throwing = new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    ApiKeyAuthenticationService service = new ApiKeyAuthenticationService(
        store, hasher, throwing, TenantId.DEFAULT, fixed(T0.plusSeconds(60)));

    assertTrue(service.authenticate("plain").isPresent());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    InMemoryApiKeyStore store = new InMemoryApiKeyStore();
    FakeHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();

    assertThrows(NullPointerException.class,
        () -> new ApiKeyAuthenticationService(null, hasher, audit));
    assertThrows(NullPointerException.class,
        () -> new ApiKeyAuthenticationService(store, null, audit));
    assertThrows(NullPointerException.class,
        () -> new ApiKeyAuthenticationService(store, hasher, null));
    assertThrows(NullPointerException.class,
        () -> new ApiKeyAuthenticationService(store, hasher, audit, TenantId.DEFAULT, null));
  }

  private static final class CollectingAuditService implements JSentinelAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
