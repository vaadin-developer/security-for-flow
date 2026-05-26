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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

/**
 * Registers the demo-side policies into the
 * {@link PolicyRegistry} resolved through
 * {@link SecurityServiceResolver}. Discovered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 *
 * <p>The single demo policy {@code documents.editor-or-admin}
 * demonstrates how the new {@code @RequiresPolicy} annotation can
 * combine role- and permission-based admission in a single rule —
 * something {@code @RequiresRole} / {@code @RequiresPermission}
 * cannot express on their own.
 */
public final class DemoPolicyInitListener implements VaadinServiceInitListener {

  /** Name of the demo policy referenced by {@code @RequiresPolicy}. */
  public static final String POLICY_EDITOR_OR_ADMIN = "documents.editor-or-admin";

  @Override
  public void serviceInit(ServiceInitEvent event) {
    PolicyRegistry registry = SecurityServiceResolver.policyRegistry();
    registry.register(Policy.named(POLICY_EDITOR_OR_ADMIN)
        .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
        .orIf(SubjectPredicates.hasPermission("document:write"))
        .deny("must be ADMIN/EDITOR or hold document:write")
        .build());
  }
}
