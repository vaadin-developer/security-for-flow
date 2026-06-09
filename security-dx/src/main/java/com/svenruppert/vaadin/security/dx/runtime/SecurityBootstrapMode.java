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
package com.svenruppert.vaadin.security.dx.runtime;

/**
 * Operational mode of the fluent bootstrap.
 *
 * <ul>
 *   <li>{@link #COMMUNITY_DEFAULTS} – minimal but safe; in-memory defaults
 *       only where they are uncritical.</li>
 *   <li>{@link #DEVELOPMENT} – verbose diagnostics, safe in-memory defaults
 *       are explicitly allowed.</li>
 *   <li>{@link #PRODUCTION} – all critical SPIs must be set; missing ones
 *       are recorded as warnings on the {@link SecurityRuntime}.</li>
 *   <li>{@link #STRICT} – any missing critical SPI is rejected via
 *       {@code SecurityBootstrapException}.</li>
 * </ul>
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable. Enum constants added in a
 *          future release would not break source compatibility.
 */
public enum SecurityBootstrapMode {
  COMMUNITY_DEFAULTS,
  DEVELOPMENT,
  PRODUCTION,
  STRICT
}
