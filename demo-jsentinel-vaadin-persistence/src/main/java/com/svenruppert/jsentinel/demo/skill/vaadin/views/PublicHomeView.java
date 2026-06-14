package com.svenruppert.jsentinel.demo.skill.vaadin.views;

import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;

/**
 * Public landing page — visible to <strong>everyone</strong>,
 * including anonymous visitors.
 *
 * <p>No {@code @VisibleFor} and no {@code @RequiresPermission}: the
 * jSentinel scanner finds no restriction annotation, so the
 * {@code LoginListener} lets the navigation through without
 * authentication.
 *
 * <p>This page is the marketing / overview surface — the rest of the
 * app (dashboard, admin views) is reachable only via the drawer
 * entries that {@code SecuredUi.link().hideWhenDenied()} reveals
 * after login.
 *
 * <p>For logged-in users a "Go to dashboard" button shortcuts to
 * {@link DashboardView}; for anonymous visitors a "Sign in" button
 * leads to {@code MyLoginView}.
 */
@Route(value = PublicHomeView.NAV, layout = MainLayout.class)
public class PublicHomeView extends Composite<VerticalLayout> {

  public static final String NAV = "";

  public PublicHomeView() {
    VerticalLayout content = getContent();
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");
    content.setAlignItems(FlexComponent.Alignment.START);

    content.add(new H1("jSentinel Vaadin Demo"));
    content.add(new Paragraph(
        "Welcome. This page is reachable without an account — "
            + "it carries no @VisibleFor / @RequiresPermission, so "
            + "the jSentinel scanner treats it as unrestricted. "
            + "After signing in, the drawer reveals the dashboard "
            + "and any admin areas your role grants."));

    boolean loggedIn = SubjectStores.subjectStore()
        .currentSubject(User.class).isPresent();
    if (loggedIn) {
      Button toDashboard = new Button("Go to dashboard",
          VaadinIcon.ARROW_RIGHT.create(),
          e -> UI.getCurrent().navigate(DashboardView.class));
      toDashboard.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
      content.add(toDashboard);
    } else {
      Button signIn = new Button("Sign in",
          VaadinIcon.SIGN_IN.create(),
          e -> UI.getCurrent().navigate(MyLoginView.class));
      signIn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
      content.add(signIn);
    }
  }
}
