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
package com.svenruppert.vaadin.security.rest;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.audit.SessionStale;
import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.InMemoryJSentinelVersionStore;
import com.svenruppert.vaadin.security.session.JSentinelVersion;
import com.svenruppert.vaadin.security.session.JSentinelVersionEnforcer;
import com.svenruppert.vaadin.security.session.JSentinelVersionKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RestJSentinelVersionFilter")
class RestJSentinelVersionFilterTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JSentinelVersionKey ALICE_KEY =
      new JSentinelVersionKey(TenantId.DEFAULT, ALICE);

  @Test
  @DisplayName("resolver without a version-context → filter is a pass-through")
  void noContextIsPassThrough() {
    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = r -> Optional.empty();

    RestJSentinelVersionFilter filter = new RestJSentinelVersionFilter(
        resolver, new JSentinelVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertTrue(filter.allow(new StubRequest("/api/things"), response));
    assertEquals(200, response.status);
    assertTrue(response.headers.isEmpty());
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("matching version → filter returns true, response untouched")
  void matchingVersionAllows() {
    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJSentinelVersionContext> resolveJSentinelVersionContext(RestRequest request) {
        return Optional.of(new RestJSentinelVersionContext(
            ALICE, TenantId.DEFAULT, JSentinelVersion.INITIAL, "sid-1"));
      }
    };

    RestJSentinelVersionFilter filter = new RestJSentinelVersionFilter(
        resolver, new JSentinelVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertTrue(filter.allow(new StubRequest("/api/things"), response));
    assertEquals(200, response.status);
    assertTrue(response.headers.isEmpty());
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("drifted version → 401 + WWW-Authenticate: SessionStale + audit emitted")
  void driftedVersionRefuses() {
    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    versionStore.increment(ALICE_KEY); // current → 1
    versionStore.increment(ALICE_KEY); // current → 2

    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJSentinelVersionContext> resolveJSentinelVersionContext(RestRequest request) {
        return Optional.of(new RestJSentinelVersionContext(
            ALICE, TenantId.DEFAULT, JSentinelVersion.INITIAL, "sid-7"));
      }
    };

    RestJSentinelVersionFilter filter = new RestJSentinelVersionFilter(
        resolver, new JSentinelVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertFalse(filter.allow(new StubRequest("/admin/secret"), response, "/admin/secret"));

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals(RestJSentinelVersionFilter.SESSION_STALE_CHALLENGE,
        response.headers.get("WWW-Authenticate"));

    assertEquals(1, audit.published.size());
    SessionStale event = (SessionStale) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals("sid-7", event.sessionId());
    assertEquals("/admin/secret", event.route());
    assertEquals(0L, event.snapshotVersion());
    assertEquals(2L, event.currentVersion());
  }

  @Test
  @DisplayName("default route is derived from request.path() when not supplied")
  void defaultRouteIsRequestPath() {
    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    versionStore.increment(ALICE_KEY); // current → 1

    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJSentinelVersionContext> resolveJSentinelVersionContext(RestRequest request) {
        return Optional.of(new RestJSentinelVersionContext(
            ALICE, TenantId.DEFAULT, JSentinelVersion.INITIAL, "sid"));
      }
    };

    RestJSentinelVersionFilter filter = new RestJSentinelVersionFilter(
        resolver, new JSentinelVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    filter.allow(new StubRequest("/api/x"), response);
    assertEquals("/api/x", ((SessionStale) audit.published.get(0)).route());
  }

  @Test
  @DisplayName("constructor + allow reject null arguments")
  void rejectNulls() {
    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = r -> Optional.empty();
    JSentinelVersionEnforcer enforcer = new JSentinelVersionEnforcer(versionStore, audit);

    assertThrows(NullPointerException.class,
        () -> new RestJSentinelVersionFilter(null, enforcer));
    assertThrows(NullPointerException.class,
        () -> new RestJSentinelVersionFilter(resolver, null));

    RestJSentinelVersionFilter filter = new RestJSentinelVersionFilter(resolver, enforcer);
    assertThrows(NullPointerException.class,
        () -> filter.allow(null, new RecordingResponse()));
    assertThrows(NullPointerException.class,
        () -> filter.allow(new StubRequest("/x"), null));
  }

  private static final class StubRequest implements RestRequest {
    private final String path;
    StubRequest(String path) { this.path = path; }
    @Override public String method() { return "GET"; }
    @Override public String path() { return path; }
    @Override public Map<String, String> headers() { return Map.of(); }
    @Override public Map<String, String> queryParameters() { return Map.of(); }
  }

  private static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override public void status(int statusCode) { this.status = statusCode; }
    @Override public void body(String body) { this.body = body; }
    @Override public void header(String name, String value) { headers.put(name, value); }
  }

  private static final class CollectingAuditService implements JSentinelAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
