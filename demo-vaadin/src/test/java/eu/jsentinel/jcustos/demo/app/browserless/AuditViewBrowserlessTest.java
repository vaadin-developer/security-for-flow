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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.AuditView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.combobox.ComboBoxTester;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.grid.GridTester;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter test for the {@code /audit}-route.
 * <p>
 * Seeds the audit pipeline with three events, binds an admin subject in
 * the SubjectStore, then navigates to {@code AuditView}. Asserts:
 * <ol>
 *   <li>the Grid shows all three events (newest-first),</li>
 *   <li>selecting the type filter narrows the result set.</li>
 * </ol>
 */
@DisplayName("AuditView — Grid + type filter")
class AuditViewBrowserlessTest extends BrowserlessTest {

  private static final Instant T0 = Instant.parse("2026-05-12T10:00:00Z");

  private final SeedingAudit audit = new SeedingAudit();

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    // Seed an admin so the directory reports hasAnyAdministrator() — keeps
    // BootstrapStateService from forwarding to /setup even if a stale
    // BootstrapWiring singleton survives the reflection reset.
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));

    audit.events.clear();
    audit.events.add(new LoginSucceeded(T0, "admin", "127.0.0.1", null));
    audit.events.add(new LoginSucceeded(T0.plusSeconds(1), "editor", "127.0.0.1", null));
    audit.events.add(new AccessDenied(T0.plusSeconds(2), "bob", "/secret", "MissingRole"));
    JSentinelServiceResolver.setJSentinelAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Grid shows seeded events newest-first; type filter narrows them")
  void gridShowsAndFilters() {
    // Bring up the UI first via a public route, then bind the admin
    // subject so the @RequiresPermission("audit:read") gate passes.
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);

    navigate(AuditView.class);

    @SuppressWarnings({"unchecked", "rawtypes"})
    GridTester<Grid<AuditEvent>, AuditEvent> grid = test($view(Grid.class).first());
    assertEquals(3, grid.size(),
        "Grid must show every seeded event");

    // Newest-first ordering — AccessDenied is the most recent event.
    assertTrue(grid.getRow(0) instanceof AccessDenied,
        "first row must be the AccessDenied (newest event)");

    // Apply the type filter to LoginSucceeded and assert only the two
    // LoginSucceeded rows remain. ComboBoxTester's selectItem(...) picks
    // by the item-label generator, which here is Class::getSimpleName.
    @SuppressWarnings({"unchecked", "rawtypes"})
    ComboBoxTester typeFilter = test($view(ComboBox.class).first());
    typeFilter.selectItem(LoginSucceeded.class.getSimpleName());

    assertEquals(2, grid.size(),
        "type filter must narrow the Grid to LoginSucceeded events only");
    assertTrue(grid.getRow(0) instanceof LoginSucceeded);
    assertTrue(grid.getRow(1) instanceof LoginSucceeded);
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  /**
   * In-memory audit service that ignores publishes but returns its
   * pre-seeded event list (filtered through {@link AuditQuery}) on every
   * {@code query} call. Lets the {@code AuditView}'s default behaviour
   * exercise the type-filter logic against deterministic data.
   */
  private static final class SeedingAudit implements JSentinelAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override public void publish(AuditEvent event) {
      // No-op: we want the Grid to reflect only the pre-seeded events,
      // not whatever the navigation flow happens to publish.
    }

    @Override public List<AuditEvent> query(AuditQuery query) {
      List<AuditEvent> result = new ArrayList<>();
      for (AuditEvent event : events) {
        if (query.matches(event)) {
          result.add(event);
        }
      }
      return result;
    }
  }

  @SuppressWarnings("unused")
  private static MyUser admin() {
    return new MyUser(1L, "Admin",
        EnumSet.copyOf(Set.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
  }
}
