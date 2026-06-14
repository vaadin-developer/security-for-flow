package com.svenruppert.jsentinel.demo.skill.vaadin.views;

import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.roles.AuthorizationRole;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.roles.VisibleFor;

import java.util.Optional;
import java.util.Set;

import static com.svenruppert.jsentinel.demo.skill.vaadin.security.roles.AuthorizationRole.*;

/**
 * Post-login landing page. Rendered inside {@link MainLayout}.
 *
 * <p>{@code @VisibleFor(USER)} — any authenticated user can land
 * here. Subjects without {@code USER} (or unauthenticated visitors)
 * are rerouted by {@code RoleAccessEvaluator}.
 *
 * <p>The drawer in {@link MainLayout} filters its own entries via
 * {@code SecuredUi.link().hideWhenDenied()} — audit / sessions /
 * roles disappear for non-ADMIN subjects, the public Home stays
 * visible to everyone.
 */
@Route(value = DashboardView.NAV, layout = MainLayout.class)
@VisibleFor(USER)
public class DashboardView extends Composite<VerticalLayout> {

  public static final String NAV = "dashboard";

  public DashboardView() {
    Optional<User> result = SubjectStores.subjectStore()
        .currentSubject(User.class);
    String displayName = result.map(User::name).orElse("Guest");
    Set<AuthorizationRole> roles = result.map(User::roles).orElse(Set.of());

    H2 greeting = new H2("Welcome, " + displayName);

    HorizontalLayout badges = new HorizontalLayout();
    badges.setSpacing(true);
    for (AuthorizationRole role : roles) {
      Span badge = new Span(role.name());
      badge.getElement().getThemeList().add("badge " + (role == ADMIN ? "error" : "success"));
      badges.add(badge);
    }

    Paragraph hint = new Paragraph(
        "Drawer entries appear based on the permissions your roles grant. "
            + "Try logging in as the regular user — the audit, sessions and "
            + "roles entries disappear automatically.");

    VerticalLayout content = getContent();
    content.add(greeting, badges, hint);
    content.setAlignItems(FlexComponent.Alignment.START);
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");
  }
}
