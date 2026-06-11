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
package com.svenruppert.jsentinel.credential.propagation;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OutboundHeaderContext")
class OutboundHeaderContextTest {

  @AfterEach
  void cleanup() { OutboundHeaderContext.clear(); }

  @Test
  @DisplayName("bind + current returns the value")
  void roundTrip() {
    OutboundHeaderContext.bind(new HeaderValue("Authorization", "Bearer abc"));
    assertEquals("Authorization", OutboundHeaderContext.current().orElseThrow().name());
    assertEquals("Bearer abc", OutboundHeaderContext.current().orElseThrow().value());
  }

  @Test
  @DisplayName("clear() sets current back to empty")
  void clearEmpties() {
    OutboundHeaderContext.bind(new HeaderValue("Authorization", "v"));
    OutboundHeaderContext.clear();
    assertTrue(OutboundHeaderContext.current().isEmpty());
  }

  @Test
  @DisplayName("Nested bind raises IllegalStateException")
  void nestedBindRaises() {
    OutboundHeaderContext.bind(new HeaderValue("X", "first"));
    assertThrows(IllegalStateException.class,
        () -> OutboundHeaderContext.bind(new HeaderValue("X", "second")));
  }

  @Test
  @DisplayName("clear() is idempotent")
  void clearIdempotent() {
    OutboundHeaderContext.clear();
    OutboundHeaderContext.clear();
  }

  @Test
  @DisplayName("Two threads see independent slots")
  void threadIsolation() throws InterruptedException {
    OutboundHeaderContext.bind(new HeaderValue("X", "main"));
    AtomicReference<Optional<HeaderValue>> other = new AtomicReference<>();
    CountDownLatch latch = new CountDownLatch(1);
    Thread worker = new Thread(() -> {
      other.set(OutboundHeaderContext.current());
      latch.countDown();
    });
    worker.start();
    latch.await();
    worker.join();
    assertTrue(other.get().isEmpty(), "worker thread must not see main's slot");
    assertEquals("main", OutboundHeaderContext.current().orElseThrow().value());
  }
}
