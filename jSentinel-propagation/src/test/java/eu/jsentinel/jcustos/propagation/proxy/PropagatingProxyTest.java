/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.proxy;

import eu.jsentinel.jcustos.annotations.PropagateToken;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.InMemoryTokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext;
import eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PropagatingProxy.wrap(...)")
class PropagatingProxyTest {

  private final TokenCredentialStore store = new InMemoryTokenCredentialStore();

  @BeforeEach
  void setup() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setTokenCredentialStore(store);
    JCustosServiceResolver.registerOutboundTokenStrategy(
        PassThroughStrategy.NAME, PassThroughStrategy.INSTANCE);
  }

  @AfterEach
  void cleanup() {
    OutboundHeaderContext.clear();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("Annotated method with bearer in the store binds the Authorization header")
  void annotatedBindsHeader() {
    store.bind(new BearerToken("abc"));
    AtomicReference<Optional<HeaderValue>> seen = new AtomicReference<>();
    DocumentClient impl = new DocumentClient() {
      @Override public String load(String id) {
        seen.set(OutboundHeaderContext.current());
        return "doc-" + id;
      }
    };
    DocumentClient wrapped = PropagatingProxy.wrap(DocumentClient.class, impl);
    String result = wrapped.load("42");
    assertEquals("doc-42", result);
    assertEquals(new HeaderValue("Authorization", "Bearer abc"),
        seen.get().orElseThrow());
    assertTrue(OutboundHeaderContext.current().isEmpty(),
        "slot must be cleared after the delegate returns");
  }

  @Test
  @DisplayName("Unannotated method does not bind a header")
  void unannotatedSkips() {
    store.bind(new BearerToken("abc"));
    AtomicReference<Optional<HeaderValue>> seen = new AtomicReference<>();
    UnannotatedClient impl = id -> { seen.set(OutboundHeaderContext.current()); return id; };
    UnannotatedClient wrapped = PropagatingProxy.wrap(UnannotatedClient.class, impl);
    wrapped.load("42");
    assertTrue(seen.get().isEmpty(), "unannotated call must NOT bind a header");
  }

  @Test
  @DisplayName("Delegate throws → slot still cleared in finally")
  void clearedOnException() {
    store.bind(new BearerToken("abc"));
    DocumentClient impl = id -> { throw new RuntimeException("boom"); };
    DocumentClient wrapped = PropagatingProxy.wrap(DocumentClient.class, impl);
    assertThrows(RuntimeException.class, () -> wrapped.load("42"));
    assertTrue(OutboundHeaderContext.current().isEmpty());
  }

  @Test
  @DisplayName("Wrap with a non-interface contract → IllegalArgumentException")
  void wrapNonInterfaceRaises() {
    assertThrows(IllegalArgumentException.class,
        () -> PropagatingProxy.wrap(String.class, "hello"));
  }

  @Test
  @DisplayName("Object methods bypass the advisor")
  void objectMethodsBypass() {
    store.bind(new BearerToken("abc"));
    DocumentClient impl = id -> id;
    DocumentClient wrapped = PropagatingProxy.wrap(DocumentClient.class, impl);
    wrapped.toString();
    wrapped.hashCode();
    assertTrue(OutboundHeaderContext.current().isEmpty());
  }

  @PropagateToken
  interface DocumentClient {
    String load(String id);
  }

  interface UnannotatedClient {
    String load(String id);
  }
}
