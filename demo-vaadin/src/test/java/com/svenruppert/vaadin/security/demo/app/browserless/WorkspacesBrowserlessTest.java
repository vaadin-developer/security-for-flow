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
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.demo.app.views.MyLoginView;
import com.svenruppert.vaadin.security.demo.app.views.components.PermissionDemoCard;
import com.svenruppert.vaadin.security.demo.app.views.components.ViewNavigationCard;
import com.svenruppert.vaadin.security.demo.app.views.workspaces.AdminWorkspace;
import com.svenruppert.vaadin.security.demo.app.views.workspaces.DemoUselessWorkspace;
import com.svenruppert.vaadin.security.demo.app.views.workspaces.NerdWorkspace;
import com.svenruppert.vaadin.security.demo.app.views.workspaces.PublicAllWorkspace;
import com.svenruppert.vaadin.security.demo.app.views.workspaces.UserWorkspace;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless test for the five role-specific workspaces. Each workspace
 * is wrapped in a tiny test-only route so we can render it inside the
 * Vaadin runtime that {@link BrowserlessTest} provides. The tests pin the
 * three observable parts that the workspace constructors actually shape:
 * the role badge, the H2 heading, and the {@code workspace-*} CSS class
 * — plus the fact that both the {@link PermissionDemoCard} and the
 * {@link ViewNavigationCard} are added to the layout.
 */
@DisplayName("Workspaces — badge / heading / theme class / composed cards")
class WorkspacesBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));

    // The PermissionDemoCard inside every workspace asks the
    // SubjectStore for the current MyUser. Bind one so isAllowed(...)
    // can run and produce a deterministic UI.
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("AdminWorkspace — ADMIN badge, 'Admin Console' heading, workspace-admin theme")
  void adminWorkspace() {
    AdminFixture view = navigate(AdminFixture.class);
    assertWorkspace(view, "ADMIN", "Admin Console", "workspace-admin");
  }

  @Test
  @DisplayName("NerdWorkspace — ADMIN+NERD badges, 'Nerd Zone' heading, workspace-nerd theme")
  void nerdWorkspace() {
    NerdFixture view = navigate(NerdFixture.class);
    VerticalLayout content = contentOf(view);
    // NerdWorkspace renders two badges in a HorizontalLayout.
    List<String> badgeTexts = new java.util.ArrayList<>();
    collectSpans(content, badgeTexts);
    assertTrue(badgeTexts.contains("ADMIN"),
        "NerdWorkspace must surface the ADMIN badge; got: " + badgeTexts);
    assertTrue(badgeTexts.contains("NERD"),
        "NerdWorkspace must surface the NERD badge; got: " + badgeTexts);
    assertEquals("Nerd Zone", findFirstChild(content, H2.class).getText());
    assertTrue(content.getClassNames().contains("workspace-nerd"));
    assertContentLayoutTuning(content);
    assertHeaderLayoutTuning(content);
    assertCardsAttached(content);
  }

  @Test
  @DisplayName("UserWorkspace — USER badge, 'My Area' heading, workspace-user theme")
  void userWorkspace() {
    UserFixture view = navigate(UserFixture.class);
    assertWorkspace(view, "USER", "My Area", "workspace-user");
  }

  @Test
  @DisplayName("PublicAllWorkspace — PUBLIC badge, 'Public Information' heading, workspace-public theme")
  void publicWorkspace() {
    PublicFixture view = navigate(PublicFixture.class);
    assertWorkspace(view, "PUBLIC", "Public Information", "workspace-public");
  }

  @Test
  @DisplayName("DemoUselessWorkspace — DEMO badge, 'Playground' heading, workspace-demo theme")
  void demoUselessWorkspace() {
    DemoFixture view = navigate(DemoFixture.class);
    assertWorkspace(view, "DEMO", "Playground", "workspace-demo");
  }

  // ── Assertion helpers ─────────────────────────────────────────

  private static void assertWorkspace(
      Composite<Div> workspaceHost,
      String expectedBadge,
      String expectedHeading,
      String expectedThemeClass) {
    VerticalLayout content = contentOf(workspaceHost);
    Span badge = findFirstChild(content, Span.class);
    assertEquals(expectedBadge, badge.getText(),
        "badge text must reflect the role label");
    assertEquals(expectedHeading, findFirstChild(content, H2.class).getText(),
        "heading must match the workspace label");
    assertTrue(content.getClassNames().contains(expectedThemeClass),
        "workspace must carry the '" + expectedThemeClass + "' theme class; got: " + content.getClassNames());
    assertContentLayoutTuning(content);
    assertHeaderLayoutTuning(content);
    assertCardsAttached(content);
  }

  /**
   * The workspace turns off the VerticalLayout's default spacing and then
   * opts into the {@code spacing-s} theme variant. Both calls are
   * mutable by PIT — pin the resulting state explicitly.
   */
  private static void assertContentLayoutTuning(VerticalLayout content) {
    assertFalse(content.isSpacing(),
        "workspace content must call setSpacing(false)");
    assertTrue(content.getThemeNames().contains("spacing-s"),
        "workspace content must opt into the 'spacing-s' theme; got: " + content.getThemeNames());
  }

  /**
   * Every workspace's header (icon + H2) is a HorizontalLayout that
   * centres its children and sets spacing. Pin both calls.
   */
  private static void assertHeaderLayoutTuning(VerticalLayout content) {
    HorizontalLayout header = headerOf(content);
    assertEquals(com.vaadin.flow.component.orderedlayout.FlexComponent.Alignment.CENTER,
        header.getAlignItems(),
        "workspace header must call setAlignItems(CENTER)");
    assertTrue(header.isSpacing(),
        "workspace header must call setSpacing(true)");
  }

  /**
   * Returns the HorizontalLayout that actually carries the H2 heading.
   * Skipping past the badge layout (the first HorizontalLayout in
   * NerdWorkspace).
   */
  private static HorizontalLayout headerOf(VerticalLayout content) {
    return content.getChildren()
        .filter(HorizontalLayout.class::isInstance)
        .map(HorizontalLayout.class::cast)
        .filter(h -> h.getChildren().anyMatch(H2.class::isInstance))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no HorizontalLayout containing an H2 in workspace content"));
  }

  /** Asserts the workspace embeds both the permission demo card and the navigation card. */
  private static void assertCardsAttached(VerticalLayout content) {
    assertNotNull(findFirstChild(content, PermissionDemoCard.class),
        "every workspace must embed a PermissionDemoCard");
    assertNotNull(findFirstChild(content, ViewNavigationCard.class),
        "every workspace must embed a ViewNavigationCard");
  }

  /**
   * Each workspace wraps its actual content in {@code Composite<Div> →
   * VerticalLayout}. The Browserless fixture adds yet another Composite
   * layer on top, so the workspace's VerticalLayout lives two nodes
   * deep. We search depth-first to stay robust against that wrapping.
   */
  private static VerticalLayout contentOf(Composite<Div> host) {
    return findDescendant(host, VerticalLayout.class);
  }

  private static <C extends Component> C findFirstChild(VerticalLayout layout, Class<C> type) {
    return findDescendant(layout, type);
  }

  private static void collectSpans(Component root, List<String> sink) {
    root.getElement().getChildren()
        .map(e -> e.getComponent().orElse(null))
        .filter(c -> c != null)
        .forEach(c -> {
          if (c instanceof Span span) sink.add(span.getText());
          collectSpans(c, sink);
        });
  }

  @SuppressWarnings("unchecked")
  private static <C extends Component> C findDescendant(Component root, Class<C> type) {
    return (C) root.getElement().getChildren()
        .map(e -> e.getComponent().orElse(null))
        .filter(c -> c != null)
        .filter(c -> type.isAssignableFrom(c.getClass()))
        .findFirst()
        .or(() -> root.getElement().getChildren()
            .map(e -> e.getComponent().orElse(null))
            .filter(c -> c != null)
            .map(c -> {
              try {
                return findDescendant(c, type);
              } catch (AssertionError ignored) {
                return null;
              }
            })
            .filter(c -> c != null)
            .findFirst())
        .orElseThrow(() -> new AssertionError(
            "no " + type.getSimpleName() + " descendant of " + root.getClass().getSimpleName()));
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  // ── Fixture routes ────────────────────────────────────────────
  // BrowserlessTest needs a routable Composite to materialize the
  // workspace via navigate(...). Each fixture is a thin wrapper that
  // just embeds the workspace under test.

  static abstract class WorkspaceFixture<W extends Composite<Div>> extends Composite<Div> {
    protected WorkspaceFixture(Supplier<W> factory) {
      getContent().add(factory.get());
    }
  }

  @Route("test/workspace-admin")
  public static class AdminFixture extends WorkspaceFixture<AdminWorkspace> {
    public AdminFixture() { super(AdminWorkspace::new); }
  }

  @Route("test/workspace-nerd")
  public static class NerdFixture extends WorkspaceFixture<NerdWorkspace> {
    public NerdFixture() { super(NerdWorkspace::new); }
  }

  @Route("test/workspace-user")
  public static class UserFixture extends WorkspaceFixture<UserWorkspace> {
    public UserFixture() { super(UserWorkspace::new); }
  }

  @Route("test/workspace-public")
  public static class PublicFixture extends WorkspaceFixture<PublicAllWorkspace> {
    public PublicFixture() { super(PublicAllWorkspace::new); }
  }

  @Route("test/workspace-demo")
  public static class DemoFixture extends WorkspaceFixture<DemoUselessWorkspace> {
    public DemoFixture() { super(DemoUselessWorkspace::new); }
  }
}
