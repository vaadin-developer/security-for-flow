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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Builder-validation tests. Construction of the actual Vaadin
 * components (SecuredButton, SecuredRouterLink, SecuredMenuItem) is
 * exercised end-to-end in the demo modules; here we focus on the
 * starter's own discipline so the unit run does not require a Vaadin
 * UI context.
 */
class SecuredUiTest {

  @Test
  void buttonWithoutRequirement_throws() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X").build());
  }

  @Test
  void buttonCanNotMixRequiresChecks() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .requiresPermission("doc:delete"));
  }

  @Test
  void buttonCanNotMixVisibilityModes() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .hideWhenDenied()
            .disableWhenDenied());
  }

  @Test
  void requiresPolicyAndRoleMutuallyExclusive() {
    // V00.73 (Prompt 011): requiresPolicy is no longer a build-time
    // UnsupportedOperationException. Builder discipline still enforces
    // "exactly one of requiresRole / requiresPermission / requiresPolicy".
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .requiresPolicy("doc.policy"));
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresPolicy("doc.policy")
            .requiresPermission("doc:read"));
  }

  @Test
  void linkWithoutTargetThrows() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.link().requiresRole("X").build());
  }

  @Test
  void linkRequiresRequirement() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.link().to(com.vaadin.flow.component.html.Div.class).build());
  }
}
