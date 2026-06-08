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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

/**
 * Placeholder audit sub-builder of the V00.72 fluent bootstrap. The
 * {@link #ringBuffer()} method is a minimal-API anchor for later
 * extension (V00.72 only records the choice; no wiring yet).
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public interface AuditBootstrap {

  AuditBootstrap ringBuffer();
}
