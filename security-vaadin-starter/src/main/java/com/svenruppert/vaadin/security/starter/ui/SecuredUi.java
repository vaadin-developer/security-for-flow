/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.vaadin.security.starter.ui;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.components.SecuredButton;
import com.svenruppert.vaadin.security.components.SecuredMenuItem;
import com.svenruppert.vaadin.security.components.SecuredRouterLink;
import com.svenruppert.vaadin.security.components.SecuredVisibility;
import com.svenruppert.vaadin.security.components.SecuredVisibilityMode;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.ComponentEventListener;
import com.vaadin.flow.component.ClickEvent;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.contextmenu.MenuItem;
import com.vaadin.flow.component.menubar.MenuBar;
import com.vaadin.flow.router.RouterLink;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Declarative fluent builders over the V00.71 {@link SecuredButton},
 * {@link SecuredRouterLink} and {@link SecuredMenuItem} components.
 * <p>
 * Discipline (V00.72 Prompts 016 / 017):
 * <ul>
 *   <li>Exactly one of {@code requiresRole}, {@code requiresPermission}
 *       or {@code requiresPolicy} must be set before {@code build()}.</li>
 *   <li>Exactly one of {@code hideWhenDenied()} or
 *       {@code disableWhenDenied()} may be set.</li>
 *   <li>Single-use: a second {@code build()} throws.</li>
 *   <li>{@code requiresPolicy(...)} is reserved for the V00.73 policy
 *       integration; calling {@code build()} after it throws
 *       {@link UnsupportedOperationException} so callers see the
 *       limitation explicitly rather than silently bypassing
 *       enforcement.</li>
 * </ul>
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public final class SecuredUi {

  private SecuredUi() {
  }

  public static SecuredButtonBuilder button(String label) {
    return new SecuredButtonBuilder(label);
  }

  public static SecuredRouterLinkBuilder link() {
    return new SecuredRouterLinkBuilder();
  }

  public static SecuredMenuItemBuilder menuItem(MenuBar parent, String label) {
    return new SecuredMenuItemBuilder(parent, label);
  }

  /** Common configuration shared by the three builders. */
  abstract static class AbstractSecuredUiBuilder<B extends AbstractSecuredUiBuilder<B>> {
    Set<RoleName> roles;
    Set<PermissionName> permissions;
    String policyName;
    SecuredVisibilityMode mode;
    boolean used;

    @SuppressWarnings("unchecked")
    final B self() {
      return (B) this;
    }

    public B requiresRole(String... roleNames) {
      Objects.requireNonNull(roleNames, "roleNames");
      assertNoCheckYet();
      Set<RoleName> tmp = new LinkedHashSet<>();
      for (String r : roleNames) {
        tmp.add(new RoleName(Objects.requireNonNull(r, "role")));
      }
      this.roles = tmp;
      return self();
    }

    public B requiresPermission(String... permissionNames) {
      Objects.requireNonNull(permissionNames, "permissionNames");
      assertNoCheckYet();
      Set<PermissionName> tmp = new LinkedHashSet<>();
      for (String p : permissionNames) {
        tmp.add(new PermissionName(Objects.requireNonNull(p, "permission")));
      }
      this.permissions = tmp;
      return self();
    }

    public B requiresPolicy(String policy) {
      Objects.requireNonNull(policy, "policy");
      assertNoCheckYet();
      this.policyName = policy;
      return self();
    }

    public B hideWhenDenied() {
      assertModeNotSet();
      this.mode = SecuredVisibilityMode.HIDE;
      return self();
    }

    public B disableWhenDenied() {
      assertModeNotSet();
      this.mode = SecuredVisibilityMode.DISABLE;
      return self();
    }

    final SecuredVisibility.Requirement requirement() {
      if (roles == null && permissions == null && policyName == null) {
        throw new IllegalStateException(
            "Exactly one of requiresRole / requiresPermission / requiresPolicy must be set");
      }
      if (policyName != null) {
        // V00.72 surface limit: policy enforcement in the Vaadin starter is deferred.
        throw new UnsupportedOperationException(
            "SecuredUi.requiresPolicy(...) is reserved for V00.73; "
                + "use @SecureRoute(policy = \"...\") on the route class instead");
      }
      return new SecuredVisibility.Requirement(roles, permissions);
    }

    final SecuredVisibilityMode modeOrDefault(SecuredVisibilityMode defaultMode) {
      return mode == null ? defaultMode : mode;
    }

    final void markUsed() {
      if (used) {
        throw new IllegalStateException("build() may only be called once on the same builder");
      }
      used = true;
    }

    private void assertNoCheckYet() {
      if (roles != null || permissions != null || policyName != null) {
        throw new IllegalStateException(
            "Only one of requiresRole / requiresPermission / requiresPolicy may be set");
      }
    }

    private void assertModeNotSet() {
      if (mode != null) {
        throw new IllegalStateException(
            "Only one of hideWhenDenied() / disableWhenDenied() may be set");
      }
    }
  }

  // ---- Button -------------------------------------------------------------

  public static final class SecuredButtonBuilder
      extends AbstractSecuredUiBuilder<SecuredButtonBuilder> {
    private final String label;
    private ComponentEventListener<ClickEvent<Button>> clickListener;

    SecuredButtonBuilder(String label) {
      this.label = Objects.requireNonNull(label, "label");
    }

    public SecuredButtonBuilder onClick(ComponentEventListener<ClickEvent<Button>> listener) {
      this.clickListener = Objects.requireNonNull(listener, "listener");
      return this;
    }

    public Button build() {
      markUsed();
      SecuredButton b = new SecuredButton(label, requirement(), modeOrDefault(SecuredVisibilityMode.DISABLE));
      if (clickListener != null) {
        b.addClickListener(clickListener);
      }
      return b;
    }
  }

  // ---- RouterLink ---------------------------------------------------------

  public static final class SecuredRouterLinkBuilder
      extends AbstractSecuredUiBuilder<SecuredRouterLinkBuilder> {
    private String text;
    private Class<? extends Component> target;

    SecuredRouterLinkBuilder() {
    }

    public SecuredRouterLinkBuilder to(Class<? extends Component> route) {
      this.target = Objects.requireNonNull(route, "route");
      return this;
    }

    public SecuredRouterLinkBuilder text(String text) {
      this.text = Objects.requireNonNull(text, "text");
      return this;
    }

    public RouterLink build() {
      markUsed();
      if (target == null) {
        throw new IllegalStateException("SecuredUi.link() requires .to(<route>)");
      }
      String effectiveText = text == null ? target.getSimpleName() : text;
      return new SecuredRouterLink(effectiveText, target, requirement(),
          modeOrDefault(SecuredVisibilityMode.HIDE));
    }
  }

  // ---- MenuItem -----------------------------------------------------------

  public static final class SecuredMenuItemBuilder
      extends AbstractSecuredUiBuilder<SecuredMenuItemBuilder> {
    private final MenuBar parent;
    private final String label;
    private ComponentEventListener<ClickEvent<MenuItem>> clickListener;

    SecuredMenuItemBuilder(MenuBar parent, String label) {
      this.parent = Objects.requireNonNull(parent, "parent");
      this.label = Objects.requireNonNull(label, "label");
    }

    public SecuredMenuItemBuilder onClick(ComponentEventListener<ClickEvent<MenuItem>> listener) {
      this.clickListener = Objects.requireNonNull(listener, "listener");
      return this;
    }

    public MenuItem build() {
      markUsed();
      MenuItem item = clickListener == null
          ? parent.addItem(label)
          : parent.addItem(label, clickListener);
      SecuredMenuItem.bind(item, requirement(), modeOrDefault(SecuredVisibilityMode.HIDE));
      return item;
    }
  }
}
