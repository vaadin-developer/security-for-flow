package com.svenruppert.jsentinel.demo.skill.vaadin.security.services;

import com.svenruppert.jsentinel.session.InMemorySessionStore;
import com.svenruppert.jsentinel.session.SessionStore;

/**
 * Lazy singleton holder for the {@link SessionStore}. Records of
 * active sessions live here so the {@code /admin/sessions} view can
 * render them via the framework's {@code SessionManagementView}.
 *
 * <p>Demo-only: in-memory, dropped on JVM exit. Swap in
 * {@code EclipseStoreSessionStore} (from
 * {@code jSentinel-persistence-eclipsestore}) for a persistent
 * backend.
 */
public final class SessionStoreProvider {

  private static final SessionStore INSTANCE = new InMemorySessionStore();

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return INSTANCE;
  }
}
