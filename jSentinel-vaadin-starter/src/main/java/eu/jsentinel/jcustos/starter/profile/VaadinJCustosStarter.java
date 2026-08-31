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
package eu.jsentinel.jcustos.starter.profile;

import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;

/**
 * Default profile for the Vaadin starter. Applied via
 * {@link eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap}
 * before any user-provided overrides; the user always wins on
 * conflicting configuration.
 *
 * <ul>
 *   <li>{@link DevelopmentDefaults} — in-memory defaults, verbose
 *       diagnostics, mode {@code DEVELOPMENT} if not overridden.</li>
 *   <li>{@link ProductionDefaults} — no in-memory defaults; mode
 *       {@code PRODUCTION}; missing critical SPIs surface as warnings
 *       on the runtime.</li>
 *   <li>{@link StrictDefaults} — same as production, but forces mode
 *       {@code STRICT}; missing critical SPIs become exceptions.</li>
 * </ul>
 *
 * @since 00.72.00
 */
public sealed interface VaadinJCustosStarter
    extends java.util.function.Consumer<VaadinJCustosBootstrap>
    permits DevelopmentDefaults, ProductionDefaults, StrictDefaults {

  static VaadinJCustosStarter developmentDefaults() {
    return DevelopmentDefaults.INSTANCE;
  }

  static VaadinJCustosStarter productionDefaults() {
    return ProductionDefaults.INSTANCE;
  }

  static VaadinJCustosStarter strictDefaults() {
    return StrictDefaults.INSTANCE;
  }

  /** The mode this profile applies (or {@code null} for "do not override"). */
  JCustosBootstrapMode preferredMode();

  /** Hook for adapter-specific configuration. */
  default void applyTo(VaadinJCustosBootstrap bootstrap) {
    JCustosBootstrapMode mode = preferredMode();
    if (mode != null) {
      bootstrap.mode(mode);
    }
  }

  /**
   * {@link java.util.function.Consumer Consumer} bridge so the profile
   * can be passed to
   * {@link VaadinJCustosBootstrap#use(java.util.function.Consumer)}.
   */
  @Override
  default void accept(VaadinJCustosBootstrap bootstrap) {
    applyTo(bootstrap);
  }
}
