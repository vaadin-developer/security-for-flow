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
package com.svenruppert.vaadin.security.authorization;

import com.svenruppert.vaadin.security.action.ActionAuthorizationService;
import com.svenruppert.vaadin.security.action.ActionPermission;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adapter-level test that pins the contract behind the two canonical
 * Vaadin patterns for permission-gated UI:
 * <ol>
 *   <li><b>Visibility</b>: an admin button calls
 *       {@code setVisible(actionService.isAllowed(...))} during render —
 *       non-permitted subjects don't see it.</li>
 *   <li><b>Server-side guard</b>: an action button is always rendered;
 *       its click-handler calls {@code requireAllowed(...)} <em>before</em>
 *       performing the side-effect — non-permitted subjects can press
 *       it but the side-effect never runs (and an
 *       {@code AccessDeniedException} is raised).</li>
 * </ol>
 * Demo modules apply both patterns through {@code PermissionDemoCard};
 * this test pins them at adapter level so the contract is asserted
 * against the {@link ActionAuthorizationService} SPI itself rather than
 * the demo-specific subject type.
 */
@DisplayName("Action-gated UI patterns — visibility + server-side guard")
class ActionGatedUiPatternTest extends BrowserlessTest {

  private static final ActionPermission ADMIN_DELETE = new ActionPermission("admin:delete");

  private final StubActionService actionService = new StubActionService();

  @BeforeEach
  void wire() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setActionAuthorizationService(actionService);
    actionService.reset();
    Fixture.deleteCalls.set(0);
  }

  @AfterEach
  void cleanUp() {
    JSentinelServiceResolver.resetAll();
  }

  // ── Pattern A — visibility driven by isAllowed ────────────────

  @Test
  @DisplayName("Permitted subject: admin button is visible")
  void permittedSubjectSeesAdminButton() {
    actionService.permitted.add(ADMIN_DELETE);
    Fixture view = navigate(Fixture.class);

    assertTrue(view.adminButton.isVisible(),
        "admin button must be visible when the subject is allowed");
  }

  @Test
  @DisplayName("Non-permitted subject: admin button is hidden")
  void nonPermittedSubjectDoesNotSeeAdminButton() {
    // permitted set is empty
    Fixture view = navigate(Fixture.class);

    assertFalse(view.adminButton.isVisible(),
        "admin button must be hidden when the subject is not allowed");
  }

  // ── Pattern B — server-side guard via requireAllowed ──────────

  @Test
  @DisplayName("Permitted subject: clicking the guarded action runs the side-effect")
  void permittedClickRunsAction() {
    actionService.permitted.add(ADMIN_DELETE);
    Fixture view = navigate(Fixture.class);

    test(view.guardedAction).click();

    assertEquals(1, Fixture.deleteCalls.get(),
        "delete-side-effect must run exactly once for a permitted click");
    assertEquals(1, actionService.requireAllowedCalls,
        "requireAllowed must be consulted exactly once per click");
  }

  @Test
  @DisplayName("Non-permitted subject: clicking the guarded action throws and the side-effect does NOT run")
  void nonPermittedClickIsBlocked() {
    Fixture view = navigate(Fixture.class);

    // The click handler swallows the AccessDeniedException so the test
    // can verify the side-effect count rather than chasing an exception
    // through Vaadin's event-dispatch frame.
    test(view.guardedAction).click();

    assertEquals(0, Fixture.deleteCalls.get(),
        "delete-side-effect must NOT run when the subject is not allowed");
    assertEquals(1, actionService.requireAllowedCalls,
        "requireAllowed must still be consulted on the disallowed click "
            + "(the guard is *server-side* — it doesn't depend on visibility)");
    assertEquals(1, Fixture.deniedCalls.get(),
        "the click handler must catch the AccessDeniedException once");
  }

  // ── Fixtures ──────────────────────────────────────────────────

  @Route("test/action-gated-ui")
  public static class Fixture extends Composite<Div> {
    static final AtomicInteger deleteCalls = new AtomicInteger();
    static final AtomicInteger deniedCalls = new AtomicInteger();

    final Button adminButton;
    final Button guardedAction;

    public Fixture() {
      ActionAuthorizationService<Object> svc =
          JSentinelServiceResolver.actionAuthorizationService();

      // Pattern A — visibility hint
      adminButton = new Button("Delete (visible only when allowed)");
      adminButton.setVisible(svc.isAllowed(null, ADMIN_DELETE));

      // Pattern B — server-side guard
      guardedAction = new Button("Delete (server-side guard)", e -> {
        try {
          svc.requireAllowed(null, ADMIN_DELETE);
          deleteCalls.incrementAndGet();
          performDelete();
        } catch (AccessDeniedException denied) {
          deniedCalls.incrementAndGet();
        }
      });

      getContent().add(adminButton, guardedAction);
    }

    private static void performDelete() {
      // Stand-in for the real action. Counted via deleteCalls.
      UI.getCurrent(); // touch the runtime so Browserless logs the click
    }
  }

  /**
   * Test-only {@link ActionAuthorizationService} keyed on a permitted set
   * of {@link ActionPermission}s. {@code requireAllowed} mirrors the
   * default contract: throw {@link AccessDeniedException} when the
   * action is not in the set.
   */
  static final class StubActionService implements ActionAuthorizationService<Object> {
    final Set<ActionPermission> permitted = new HashSet<>();
    int isAllowedCalls = 0;
    int requireAllowedCalls = 0;

    void reset() {
      permitted.clear();
      isAllowedCalls = 0;
      requireAllowedCalls = 0;
    }

    @Override public boolean isAllowed(Object subject, ActionPermission permission) {
      isAllowedCalls++;
      return permitted.contains(permission);
    }

    @Override public void requireAllowed(Object subject, ActionPermission permission) {
      requireAllowedCalls++;
      if (!permitted.contains(permission)) {
        throw new AccessDeniedException("Missing action permission: " + permission.name());
      }
    }
  }
}
