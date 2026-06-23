package com.svenruppert.jsentinel.demo.skill.rest.security;

import com.svenruppert.jsentinel.session.SessionStore;
import com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap.JSentinelStorageProvider;

/**
 * Replacement for the layer-1 in-memory provider — now delegates to
 * the Eclipse-Store-backed
 * {@link com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage}
 * via {@link JSentinelStorageProvider}.
 */
public final class SessionStoreProvider {

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return JSentinelStorageProvider.framework().sessionStore();
  }
}
