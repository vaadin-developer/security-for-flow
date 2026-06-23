package com.svenruppert.jsentinel.demo.skill.vaadin.security.services;

import com.svenruppert.jsentinel.session.SessionStore;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap.JSentinelStorageProvider;

/**
 * Replacement for the {@code vaadin-jsentinel} provider — now
 * delegates to the Eclipse-Store-backed
 * {@link com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage}
 * via {@link JSentinelStorageProvider}.
 *
 * <p>Session records survive JVM restarts as long as the
 * {@code ./data/jsentinel-vaadin-persistence} directory survives.
 */
public final class SessionStoreProvider {

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return JSentinelStorageProvider.framework().sessionStore();
  }
}
