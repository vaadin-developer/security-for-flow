package com.svenruppert.jsentinel.demo.skill.vaadin.security;

import com.svenruppert.jsentinel.authorization.LoginListener;
import com.svenruppert.jsentinel.authorization.LoginView;
import com.vaadin.flow.component.Component;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.DashboardView;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.MyLoginView;

/**
 * Wires the framework's authentication-phase navigation listener to
 * the application's login and default route classes. Registered via
 * {@code META-INF/services/com.svenruppert.jsentinel.authorization.LoginListener}.
 */
public class MyLoginListener extends LoginListener<User> {

  @Override
  public void notARestrictedTarget(Class<?> navigationTarget) {
    logger().info("Unrestricted navigation target — no login required: {}",
        navigationTarget.getSimpleName());
  }

  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return DashboardView.class;
  }
}
