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
package com.svenruppert.jsentinel.credential.propagation.vaadin;

import com.svenruppert.jsentinel.credential.propagation.ThreadSafeTokenCredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("Vaadin default store does NOT carry the ThreadSafe marker")
class ThreadSafeMarkerAbsenceTest {

  @Test
  @DisplayName("VaadinSessionTokenCredentialStore is NOT marked thread-safe")
  void markerAbsent() {
    Object store = new VaadinSessionTokenCredentialStore();
    assertFalse(store instanceof ThreadSafeTokenCredentialStore,
        "VaadinSessionTokenCredentialStore must NOT claim the marker — Vaadin's session "
            + "is single-thread per UI; background-thread access is an application bug.");
  }
}
