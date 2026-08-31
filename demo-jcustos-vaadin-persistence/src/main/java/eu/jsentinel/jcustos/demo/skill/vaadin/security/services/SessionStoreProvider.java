package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosStorageProvider;

/**
 * Replacement for the {@code vaadin-jcustos} provider — now
 * delegates to the Eclipse-Store-backed
 * {@link eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage}
 * via {@link JCustosStorageProvider}.
 *
 * <p>Session records survive JVM restarts as long as the
 * {@code ./data/jcustos-vaadin-persistence} directory survives.
 */
public final class SessionStoreProvider {

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return JCustosStorageProvider.framework().sessionStore();
  }
}
