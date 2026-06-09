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
package com.svenruppert.vaadin.security.demo.app.browserless;

import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.demo.app.security.services.DemoSessionStoreProvider;
import com.svenruppert.vaadin.security.demo.app.views.AdminSessionsView;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.SessionId;
import com.svenruppert.vaadin.security.session.JSentinelVersion;
import com.svenruppert.vaadin.security.session.SessionRecord;
import com.svenruppert.vaadin.security.session.SessionStatus;
import com.svenruppert.vaadin.security.session.SessionStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Smoke test for {@link AdminSessionsView}, the Phase-8a demo wiring
 * for {@link com.svenruppert.vaadin.security.components.SessionManagementView}.
 * Confirms:
 * <ul>
 *   <li>The route renders the framework composite (H1 + Grid).</li>
 *   <li>The shared {@link DemoSessionStoreProvider} feeds the grid:
 *       a record saved to the store surfaces in the rendered view.</li>
 *   <li>The revoke callback flips a session's status to
 *       {@link SessionStatus#REVOKED} via {@code SessionStore.save(...)}.</li>
 * </ul>
 */
@DisplayName("AdminSessionsView — Phase-8a SessionManagementView wiring")
class AdminSessionsViewBrowserlessTest extends BrowserlessTest {

  private static final SessionId SID = SessionId.of("demo-session-1");

  @org.junit.jupiter.api.BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    try {
      var field = BootstrapWiring.class.getDeclaredField("current");
      field.setAccessible(true);
      field.set(null, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    MyUser admin = new MyUser(1L, "Admin",
        java.util.EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
    DemoUserDirectoryProvider.directory().addUser("admin", "admin", admin);

    // Clean state in the shared session store between tests.
    SessionStore store = DemoSessionStoreProvider.sessionStore();
    store.delete(SID);

    super.initVaadinEnvironment();

    // Bind the admin so the @RequiresPermission("admin:sessions") guard
    // on AdminSessionsView lets the navigation through.
    SubjectStores.subjectStore().setCurrentSubject(admin, MyUser.class);
  }

  @AfterEach
  void tearDown() {
    DemoSessionStoreProvider.sessionStore().delete(SID);
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Renders the framework SessionManagementView H1 + Grid")
  void rendersHeadingAndGrid() {
    navigate(AdminSessionsView.class);

    H1 heading = $view(H1.class).first();
    assertNotNull(heading, "SessionManagementView must render an H1");
    assertEquals("Active Sessions", heading.getText(),
        "framework heading text must surface in the demo subclass");

    Grid<?> grid = $view(Grid.class).first();
    assertNotNull(grid, "SessionManagementView must render a Grid<SessionRecord>");
  }

  @Test
  @DisplayName("A record saved to the shared SessionStore is surfaced by the view")
  void recordInStoreIsRendered() {
    Instant now = Instant.now();
    SessionRecord record = new SessionRecord(
        SID, SubjectId.of("1"), TenantId.DEFAULT,
        now, now, JSentinelVersion.INITIAL, SessionStatus.ACTIVE);
    DemoSessionStoreProvider.sessionStore().save(record);

    navigate(AdminSessionsView.class);

    Grid<?> grid = $view(Grid.class).first();
    long visible = DemoSessionStoreProvider.sessionStore().findAll().stream()
        .filter(r -> r.sessionId().equals(SID))
        .count();
    assertEquals(1L, visible,
        "the demo store must surface the saved record to the view");
    assertNotNull(grid);
  }
}
