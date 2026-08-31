package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JSentinelStorageProvider;

/**
 * Replacement for the {@code vaadin-jsentinel} provider — now
 * delegates to the Eclipse-Store-backed
 * {@link eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJSentinelStorage}
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
