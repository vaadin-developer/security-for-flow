/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.audit.NoopSecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class SecurityTestExtensionTest {

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("beforeEach clears a previously cached non-fallback service")
  void beforeEachClearsCache() {
    RecordingAuditSink custom = new RecordingAuditSink();
    SecurityServiceResolver.setSecurityAuditService(custom);
    assertSame(custom, SecurityServiceResolver.securityAuditService());

    new SecurityTestExtension().beforeEach(null);

    assertNotSame(custom, SecurityServiceResolver.securityAuditService());
    assertSame(NoopSecurityAuditService.INSTANCE,
        SecurityServiceResolver.securityAuditService());
  }

  @Test
  @DisplayName("afterEach clears a previously cached non-fallback service")
  void afterEachClearsCache() {
    RecordingAuditSink custom = new RecordingAuditSink();
    SecurityServiceResolver.setSecurityAuditService(custom);

    new SecurityTestExtension().afterEach(null);

    assertSame(NoopSecurityAuditService.INSTANCE,
        SecurityServiceResolver.securityAuditService());
  }
}
