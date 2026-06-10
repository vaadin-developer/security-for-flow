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
import com.svenruppert.jsentinel.demo.app.views.AdminRolesView;
import com.svenruppert.jsentinel.demo.app.views.AdminSessionsView;
import com.svenruppert.jsentinel.demo.app.views.AdminView;
import com.svenruppert.jsentinel.demo.app.views.AuditView;
import com.svenruppert.jsentinel.demo.app.views.NerdView;
import com.svenruppert.jsentinel.demo.app.views.PublicView;
import com.svenruppert.jsentinel.demo.app.views.SecureRouteDemoView;
import com.svenruppert.jsentinel.demo.app.views.components.ViewNavigationCard;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouterLink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ViewNavigationCard — RouterLinks + Phase-8a SecuredRouterLinks + layout")
class ViewNavigationCardBrowserlessTest extends BrowserlessTest {

  /** Plain {@link RouterLink}s rendered by the first row of the card. */
  private static final Map<String, Class<?>> EXPECTED_PLAIN_LINKS = Map.of(
      "/admin (ADMIN)", AdminView.class,
      "/admin/roles (admin:roles)", AdminRolesView.class,
      "/nerd (ADMIN, NERD)", NerdView.class,
      "/audit (audit:read)", AuditView.class,
      "/public (open)", PublicView.class);

  /**
   * SecuredRouterLinks rendered by the Phase-8a row of the card. They
   * are subclasses of {@link RouterLink} and therefore counted in any
   * generic {@code $view(RouterLink.class).all()} query.
   */
  private static final Map<String, Class<?>> EXPECTED_SECURED_LINKS = Map.of(
      "/admin/roles (HIDE)", AdminRolesView.class,
      "/admin/sessions (HIDE)", AdminSessionsView.class,
      "/audit (DISABLE)", AuditView.class);

  /**
   * V00.72 SecuredUi.link(...) entries rendered by the Pattern D row.
   * Same target classes as Phase-8a — the comparison value is in the
   * fluent builder versus the explicit Requirement constructor. The
   * trailing entry uses role-mode + a route protected by
   * {@code @SecureRoute} (V00.72 starter).
   */
  private static final Map<String, Class<?>> EXPECTED_SECURED_UI_LINKS = Map.of(
      "/admin/roles · SecuredUi HIDE", AdminRolesView.class,
      "/admin/sessions · SecuredUi HIDE", AdminSessionsView.class,
      "/audit · SecuredUi DISABLE", AuditView.class,
      "/secure-route-demo · SecuredUi DISABLE (ADMIN, NERD)", SecureRouteDemoView.class);

  /**
   * BrowserlessTest's superclass annotates {@code initVaadinEnvironment()}
   * with {@code @BeforeEach}, and it builds the MockVaadinService which
   * fires {@code VaadinServiceInitListener}s — including our
   * {@code BootstrapServiceInitListener}, which eagerly calls
   * {@code BootstrapWiring.instance()}. If we wait until our own
   * {@code @BeforeEach} to seed an admin, the bootstrap startup runs
   * first and throws because the directory has no administrator. We
   * therefore override the super hook and seed the directory <em>before</em>
   * delegating up.
   */
  @org.junit.jupiter.api.BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    try {
      resetBootstrapWiringSingleton();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    super.initVaadinEnvironment();
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Card carries the 'view-navigation-card' class, setSpacing(false) + spacing-s theme, H3 heading")
  void cardSkeleton() {
    navigate(ViewNavigationCardFixture.class);

    VerticalLayout root = $view(VerticalLayout.class).all().stream()
        .filter(v -> v.getClassNames().contains("view-navigation-card"))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no VerticalLayout with class 'view-navigation-card' rendered"));
    assertFalse(root.isSpacing(),
        "card must call setSpacing(false)");
    assertTrue(root.getThemeNames().contains("spacing-s"),
        "card must carry the 'spacing-s' theme; got: " + root.getThemeNames());

    assertEquals("Standalone views (view-level security)",
        $view(H3.class).first().getText(),
        "card must render the H3 heading");
  }

  @Test
  @DisplayName("RouterLinks point to the expected plain + Phase-8a targets")
  void linksMatchExpectedTargets() {
    // Bind the admin subject before navigation so every SecuredRouterLink
    // resolves to "allowed" — HIDE mode keeps the link in the layout,
    // DISABLE mode leaves it enabled. Without a subject, the two HIDE
    // links disappear from the DOM. See the dedicated guard test below.
    SubjectStores.subjectStore().setCurrentSubject(adminUser(), MyUser.class);

    navigate(ViewNavigationCardFixture.class);

    int expectedTotal = EXPECTED_PLAIN_LINKS.size()
        + EXPECTED_SECURED_LINKS.size()
        + EXPECTED_SECURED_UI_LINKS.size();
    List<RouterLink> links = $view(RouterLink.class).all();
    assertEquals(expectedTotal, links.size(),
        "card must render " + expectedTotal + " RouterLinks "
            + "(5 plain + 3 Phase-8a + 4 SecuredUi); got: " + links.size());

    List<String> texts = links.stream().map(RouterLink::getText).toList();
    for (String expectedLabel : EXPECTED_PLAIN_LINKS.keySet()) {
      assertTrue(texts.contains(expectedLabel),
          "missing plain RouterLink labelled '" + expectedLabel + "'; got: " + texts);
    }
    for (String expectedLabel : EXPECTED_SECURED_LINKS.keySet()) {
      assertTrue(texts.contains(expectedLabel),
          "missing SecuredRouterLink labelled '" + expectedLabel + "'; got: " + texts);
    }
    for (String expectedLabel : EXPECTED_SECURED_UI_LINKS.keySet()) {
      assertTrue(texts.contains(expectedLabel),
          "missing SecuredUi link labelled '" + expectedLabel + "'; got: " + texts);
    }
  }

  @Test
  @DisplayName("Without a current subject the HIDE-mode SecuredRouterLinks disappear")
  void hideModeRemovesLinksForAnonymous() {
    // No setCurrentSubject(...) — anonymous viewer.
    navigate(ViewNavigationCardFixture.class);

    List<RouterLink> links = $view(RouterLink.class).all();
    List<String> texts = links.stream().map(RouterLink::getText).toList();

    // Plain RouterLinks always render — view-level guard is server-side.
    for (String expectedLabel : EXPECTED_PLAIN_LINKS.keySet()) {
      assertTrue(texts.contains(expectedLabel),
          "plain RouterLink '" + expectedLabel + "' must render regardless of subject");
    }
    // HIDE-mode SecuredRouterLinks must be gone.
    assertFalse(texts.contains("/admin/roles (HIDE)"),
        "HIDE-mode SecuredRouterLink must disappear when subject lacks permission");
    assertFalse(texts.contains("/admin/sessions (HIDE)"),
        "HIDE-mode SecuredRouterLink must disappear when subject lacks permission");
    // DISABLE-mode SecuredRouterLink stays in the layout (just disabled).
    assertTrue(texts.contains("/audit (DISABLE)"),
        "DISABLE-mode SecuredRouterLink must stay rendered even without permission");
    // Pattern D — same semantics, fluent builder. HIDE entries disappear,
    // DISABLE entries stay rendered.
    assertFalse(texts.contains("/admin/roles · SecuredUi HIDE"),
        "HIDE-mode SecuredUi.link must disappear when subject lacks permission");
    assertFalse(texts.contains("/admin/sessions · SecuredUi HIDE"),
        "HIDE-mode SecuredUi.link must disappear when subject lacks permission");
    assertTrue(texts.contains("/audit · SecuredUi DISABLE"),
        "DISABLE-mode SecuredUi.link must stay rendered even without permission");
    assertTrue(texts.contains("/secure-route-demo · SecuredUi DISABLE (ADMIN, NERD)"),
        "DISABLE-mode SecuredUi.link (role-based) must stay rendered even without subject");
  }

  private static MyUser adminUser() {
    return new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
  }

  @Test
  @DisplayName("Plain RouterLinks live inside the first spaced HorizontalLayout")
  void linksRowIsSpaced() {
    navigate(ViewNavigationCardFixture.class);

    // Filter on the *exact* RouterLink class so the SecuredRouterLink
    // row (which extends RouterLink) is excluded.
    HorizontalLayout row = $view(HorizontalLayout.class).all().stream()
        .filter(l -> l.getChildren()
            .anyMatch(c -> c.getClass() == RouterLink.class))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no HorizontalLayout carrying plain RouterLinks"));
    assertTrue(row.isSpacing(),
        "the plain-RouterLink row must call setSpacing(true)");
    long linkCount = row.getChildren()
        .filter(c -> c.getClass() == RouterLink.class)
        .count();
    assertEquals(EXPECTED_PLAIN_LINKS.size(), linkCount,
        "all plain RouterLinks must be added to the same HorizontalLayout");
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  @Route("test/view-navigation-card")
  public static class ViewNavigationCardFixture extends Composite<Div> {
    public ViewNavigationCardFixture() {
      getContent().add(new ViewNavigationCard());
    }
  }
}
