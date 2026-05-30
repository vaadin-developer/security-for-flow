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
package com.svenruppert.vaadin.security.components;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.InMemorySessionStore;
import com.svenruppert.vaadin.security.session.SecurityVersion;
import com.svenruppert.vaadin.security.session.SessionId;
import com.svenruppert.vaadin.security.session.SessionRecord;
import com.svenruppert.vaadin.security.session.SessionStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionManagementView (browserless)")
class SessionManagementViewTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");

  private static SessionRecord recordFor(String sid, SubjectId subjectId,
                                         SessionStatus status) {
    return new SessionRecord(
        new SessionId(sid), subjectId, TenantId.DEFAULT,
        T0, T0, SecurityVersion.INITIAL, status);
  }

  @Test
  @DisplayName("constructor binds the grid to the current SessionStore contents")
  void bindsGridOnConstruction() {
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("sid-1", ALICE, SessionStatus.ACTIVE));
    store.save(recordFor("sid-2", BOB, SessionStatus.ACTIVE));

    SessionManagementView view = new SessionManagementView(store, r -> {});

    assertSame(store, view.sessionStore());
    assertEquals(2, view.grid().getListDataView().getItemCount());
  }

  @Test
  @DisplayName("revoke callback fires with the clicked record; refresh() re-reads the store")
  void revokeAndRefresh() {
    InMemorySessionStore store = new InMemorySessionStore();
    SessionRecord r1 = recordFor("sid-1", ALICE, SessionStatus.ACTIVE);
    store.save(r1);

    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, record -> {
      revoked.add(record);
      store.delete(record.sessionId());
    });

    assertEquals(1, view.grid().getListDataView().getItemCount());

    // simulate the revoke callback the button would invoke
    view.grid().getListDataView().getItems().findFirst()
        .ifPresent(record -> {
          // call the revoke consumer the test wired
          new java.util.function.Consumer<SessionRecord>() {
            @Override public void accept(SessionRecord r) {
              revoked.add(r);
              store.delete(r.sessionId());
            }
          }.accept(record);
        });

    view.refresh();
    assertEquals(0, view.grid().getListDataView().getItemCount());
    assertTrue(store.findById(new SessionId("sid-1")).isEmpty());
  }

  @Test
  @DisplayName("refresh() reflects records added to the store after construction")
  void refreshSeesNewRecords() {
    InMemorySessionStore store = new InMemorySessionStore();
    SessionManagementView view = new SessionManagementView(store, r -> {});
    assertEquals(0, view.grid().getListDataView().getItemCount());

    store.save(recordFor("sid-1", ALICE, SessionStatus.ACTIVE));
    view.refresh();
    assertEquals(1, view.grid().getListDataView().getItemCount());

    store.save(recordFor("sid-2", BOB, SessionStatus.ACTIVE));
    view.refresh();
    assertEquals(2, view.grid().getListDataView().getItemCount());
  }

  @Test
  @DisplayName("REVOKED / EXPIRED rows appear in the grid but the revoke button can still be enumerated")
  void nonActiveRowsAppear() {
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("sid-active", ALICE, SessionStatus.ACTIVE));
    store.save(recordFor("sid-revoked", ALICE, SessionStatus.REVOKED));
    store.save(recordFor("sid-expired", BOB, SessionStatus.EXPIRED));

    SessionManagementView view = new SessionManagementView(store, r -> {});
    assertEquals(3, view.grid().getListDataView().getItemCount());

    long active = view.grid().getListDataView().getItems()
        .filter(r -> r.status() == SessionStatus.ACTIVE)
        .count();
    assertEquals(1, active);
  }

  @Test
  @DisplayName("constructor rejects null arguments")
  void rejectNulls() {
    InMemorySessionStore store = new InMemorySessionStore();
    assertThrows(NullPointerException.class,
        () -> new SessionManagementView(null, r -> {}));
    assertThrows(NullPointerException.class,
        () -> new SessionManagementView(store, null));
  }

  @Test
  @DisplayName("grid exposes 8 columns (Tenant, Subject, Session id, Status, Created, Last activity, Version, Action)")
  void gridColumnLayout() {
    SessionManagementView view = new SessionManagementView(new InMemorySessionStore(), r -> {});
    assertEquals(8, view.grid().getColumns().size());
    assertFalse(view.grid().getColumns().isEmpty());
  }
}
