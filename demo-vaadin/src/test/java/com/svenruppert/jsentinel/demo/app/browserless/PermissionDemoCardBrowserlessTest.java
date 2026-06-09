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
package com.svenruppert.jsentinel.demo.app.browserless;

import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.demo.app.security.bootstrap.BootstrapWiring;
import com.svenruppert.jsentinel.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.jsentinel.demo.app.security.model.MyUser;
import com.svenruppert.jsentinel.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.jsentinel.demo.app.views.MyLoginView;
import com.svenruppert.jsentinel.demo.app.views.components.PermissionDemoCard;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.H4;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless tests for {@link PermissionDemoCard}. The card has two
 * very different code paths:
 * <ol>
 *   <li><b>Pattern A — UX adaptation</b>: render an Assign-something
 *       button only when {@code isAllowed(...)} returns true; render a
 *       fallback Span otherwise.</li>
 *   <li><b>Pattern B — Server-side guard</b>: render every button, but
 *       on click call {@code requireAllowed(...)} which either succeeds
 *       (success Notification) or throws {@code AccessDeniedException}
 *       and surfaces a denied Notification.</li>
 * </ol>
 * The matrix is exercised with three subject configurations:
 * ADMIN (every permission), USER-only (just {@code demo:view}), and an
 * anonymous run (no SubjectStore subject bound).
 */
@DisplayName("PermissionDemoCard — visibility & server-side guard")
class PermissionDemoCardBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  // ── Layout / class hooks ───────────────────────────────────────

  @Test
  @DisplayName("Card renders the 'permission-demo-card' wrapper with both H3 headings and the spacing-s theme")
  void cardSkeleton() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    VerticalLayout root = $view(VerticalLayout.class).all().stream()
        .filter(v -> v.getClassNames().contains("permission-demo-card"))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no VerticalLayout with class 'permission-demo-card' rendered"));
    assertTrue(root.getClassNames().contains("permission-demo-card"),
        "root must carry the 'permission-demo-card' class");
    assertFalse(root.isSpacing(),
        "card must call setSpacing(false)");
    assertTrue(root.getThemeNames().contains("spacing-s"),
        "card must opt into the 'spacing-s' theme; got: " + root.getThemeNames());

    assertEquals("Permission demonstration",
        $view(H3.class).first().getText(),
        "card must render the H3 'Permission demonstration' heading");

    List<String> h4 = $view(H4.class).all().stream().map(H4::getText).toList();
    assertTrue(h4.stream().anyMatch(t -> t.startsWith("Pattern A")),
        "card must render the Pattern A H4; got: " + h4);
    assertTrue(h4.stream().anyMatch(t -> t.startsWith("Pattern B")),
        "card must render the Pattern B H4; got: " + h4);
  }

  // ── Pattern A — UX adaptation ──────────────────────────────────

  @Test
  @DisplayName("Pattern A: admin sees three visible-only buttons (demo:view, demo:edit, demo:admin)")
  void patternAAdminShowsThreeButtons() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternA = visibilityRow();
    List<String> labels = labelsOf(patternA);

    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:view)")),
        "admin must see the demo:view button; got: " + labels);
    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:edit)")),
        "admin must see the demo:edit button; got: " + labels);
    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:admin)")),
        "admin must see the demo:admin button; got: " + labels);
    assertEquals(3, buttonsOf(patternA).size(),
        "admin must see exactly three Pattern A buttons");
    assertTrue(spansOf(patternA).isEmpty(),
        "no fallback Span must be rendered when at least one button is visible");
  }

  @Test
  @DisplayName("Pattern A: USER-only sees the demo:view button but not edit/admin")
  void patternAUserShowsOnlyView() {
    bind(new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternA = visibilityRow();
    List<String> labels = labelsOf(patternA);

    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:view)")),
        "USER must see the demo:view button; got: " + labels);
    assertFalse(labels.stream().anyMatch(l -> l.contains("(demo:edit)")),
        "USER must NOT see the demo:edit button; got: " + labels);
    assertFalse(labels.stream().anyMatch(l -> l.contains("(demo:admin)")),
        "USER must NOT see the demo:admin button; got: " + labels);
  }

  @Test
  @DisplayName("Pattern A: anonymous (no subject) renders the fallback Span instead of any button")
  void patternAAnonymousShowsFallback() {
    // No bind() — leave SubjectStore empty.
    navigate(MyLoginView.class); // bring up a UI context
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternA = visibilityRow();
    assertTrue(buttonsOf(patternA).isEmpty(),
        "anonymous must not see any Pattern A button");
    List<Span> fallback = spansOf(patternA);
    assertEquals(1, fallback.size(),
        "anonymous must see exactly the fallback Span");
    assertEquals("(No demo permissions for this user — nothing visible.)",
        fallback.get(0).getText(),
        "fallback Span must carry the expected message");
  }

  // ── Pattern B — server-side guard ─────────────────────────────

  @Test
  @DisplayName("Pattern B: every row carries three buttons regardless of subject")
  void patternBAlwaysThreeButtons() {
    bind(new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternB = enforcementRow();
    List<Button> buttons = buttonsOf(patternB);
    assertEquals(3, buttons.size(),
        "Pattern B must render all three demo buttons regardless of permission set");
    List<String> labels = labelsOf(patternB);
    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:view)")));
    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:edit)")));
    assertTrue(labels.stream().anyMatch(l -> l.contains("(demo:admin)")));
  }

  @Test
  @DisplayName("Pattern B: clicking an allowed button surfaces an 'OK — ... executed.' success notification")
  void patternBPermittedClickShowsSuccess() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternB = enforcementRow();
    Button viewButton = buttonByPermission(patternB, "demo:view");
    test(viewButton).click();

    assertNotification("OK — 'demo:view' executed.");
  }

  @Test
  @DisplayName("Pattern B: clicking a denied button surfaces a 'Denied — missing ...' notification")
  void patternBDeniedClickShowsDenied() {
    bind(new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternB = enforcementRow();
    Button adminButton = buttonByPermission(patternB, "demo:admin");
    test(adminButton).click();

    assertNotification("Denied — missing 'demo:admin'.");
  }

  @Test
  @DisplayName("Pattern B: USER-permitted button + USER-denied button surface different notifications")
  void patternBMixedNotifications() {
    bind(new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER)));
    navigate(PermissionDemoCardFixture.class);

    HorizontalLayout patternB = enforcementRow();
    test(buttonByPermission(patternB, "demo:view")).click();
    test(buttonByPermission(patternB, "demo:edit")).click();

    assertNotification("OK — 'demo:view' executed.");
    assertNotification("Denied — missing 'demo:edit'.");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private void bind(MyUser user) {
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(user, MyUser.class);
  }

  private HorizontalLayout visibilityRow() {
    // The card's content is: H3, H4(Pattern A), Paragraph, HRow(visibility),
    // H4(Pattern B), Paragraph, HRow(enforcement). Two HRows; the first is
    // Pattern A (UX adaptation), the second is Pattern B (server-side guard).
    return horizontalLayouts().get(0);
  }

  private HorizontalLayout enforcementRow() {
    return horizontalLayouts().get(1);
  }

  private List<HorizontalLayout> horizontalLayouts() {
    return $view(HorizontalLayout.class).all().stream()
        .filter(l -> isInside(l, "permission-demo-card"))
        .toList();
  }

  private static boolean isInside(Component c, String parentClass) {
    Component parent = c.getParent().orElse(null);
    while (parent != null) {
      if (parent instanceof com.vaadin.flow.component.HasStyle hs
          && hs.getClassNames().contains(parentClass)) return true;
      parent = parent.getParent().orElse(null);
    }
    return false;
  }

  private static List<Button> buttonsOf(HorizontalLayout row) {
    return row.getChildren()
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .toList();
  }

  private static List<Span> spansOf(HorizontalLayout row) {
    return row.getChildren()
        .filter(Span.class::isInstance)
        .map(Span.class::cast)
        .toList();
  }

  private static List<String> labelsOf(HorizontalLayout row) {
    return buttonsOf(row).stream().map(Button::getText).toList();
  }

  private static Button buttonByPermission(HorizontalLayout row, String permissionToken) {
    return buttonsOf(row).stream()
        .filter(b -> b.getText().contains("(" + permissionToken + ")"))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no button referencing '" + permissionToken + "' in row; got: " + labelsOf(row)));
  }

  @SuppressWarnings("unchecked")
  private static <C extends Component> C findDescendant(Component root, Class<C> type) {
    return root.getElement().getChildren()
        .map(e -> e.getComponent().orElse(null))
        .filter(c -> c != null)
        .map(c -> type.isInstance(c) ? (C) c : findDescendantOrNull(c, type))
        .filter(c -> c != null)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no " + type.getSimpleName() + " descendant of " + root.getClass().getSimpleName()));
  }

  @SuppressWarnings("unchecked")
  private static <C extends Component> C findDescendantOrNull(Component root, Class<C> type) {
    try {
      return findDescendant(root, type);
    } catch (AssertionError ignored) {
      return null;
    }
  }

  private void assertNotification(String expectedText) {
    List<String> texts = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .toList();
    assertTrue(texts.stream().anyMatch(t -> t.contains(expectedText)),
        "expected a Notification containing '" + expectedText + "'; got: " + texts);
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  /**
   * Test-only fixture route that just embeds a {@link PermissionDemoCard}
   * so we can navigate to it from BrowserlessTest.
   */
  @Route("test/permission-demo-card")
  public static class PermissionDemoCardFixture extends Composite<Div> {
    public PermissionDemoCardFixture() {
      getContent().add(new PermissionDemoCard());
    }
  }
}
