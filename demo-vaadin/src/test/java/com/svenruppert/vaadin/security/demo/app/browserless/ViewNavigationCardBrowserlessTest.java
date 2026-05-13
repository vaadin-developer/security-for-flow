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

import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.demo.app.views.AdminRolesView;
import com.svenruppert.vaadin.security.demo.app.views.AdminView;
import com.svenruppert.vaadin.security.demo.app.views.AuditView;
import com.svenruppert.vaadin.security.demo.app.views.NerdView;
import com.svenruppert.vaadin.security.demo.app.views.PublicView;
import com.svenruppert.vaadin.security.demo.app.views.components.ViewNavigationCard;
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

@DisplayName("ViewNavigationCard — five RouterLinks + layout")
class ViewNavigationCardBrowserlessTest extends BrowserlessTest {

  private static final Map<String, Class<?>> EXPECTED_LINKS = Map.of(
      "/admin (ADMIN)", AdminView.class,
      "/admin/roles (admin:roles)", AdminRolesView.class,
      "/nerd (ADMIN, NERD)", NerdView.class,
      "/audit (audit:read)", AuditView.class,
      "/public (open)", PublicView.class);

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
    SecurityServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    super.initVaadinEnvironment();
  }

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
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
  @DisplayName("The five RouterLinks point to the expected standalone views")
  void linksMatchExpectedTargets() {
    navigate(ViewNavigationCardFixture.class);

    List<RouterLink> links = $view(RouterLink.class).all();
    assertEquals(EXPECTED_LINKS.size(), links.size(),
        "card must render exactly " + EXPECTED_LINKS.size() + " RouterLinks; got: " + links.size());

    for (RouterLink link : links) {
      Class<?> expected = EXPECTED_LINKS.get(link.getText());
      assertTrue(expected != null,
          "unexpected RouterLink text: '" + link.getText() + "'");
    }
    // every expected label is present
    List<String> texts = links.stream().map(RouterLink::getText).toList();
    for (String expectedLabel : EXPECTED_LINKS.keySet()) {
      assertTrue(texts.contains(expectedLabel),
          "missing RouterLink labelled '" + expectedLabel + "'; got: " + texts);
    }
  }

  @Test
  @DisplayName("RouterLinks live inside a HorizontalLayout that calls setSpacing(true)")
  void linksRowIsSpaced() {
    navigate(ViewNavigationCardFixture.class);

    HorizontalLayout row = $view(HorizontalLayout.class).all().stream()
        .filter(l -> l.getChildren().anyMatch(RouterLink.class::isInstance))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no HorizontalLayout carrying RouterLinks"));
    assertTrue(row.isSpacing(),
        "the RouterLink row must call setSpacing(true)");
    long linkCount = row.getChildren().filter(RouterLink.class::isInstance).count();
    assertEquals(EXPECTED_LINKS.size(), linkCount,
        "all RouterLinks must be added to the same HorizontalLayout");
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
