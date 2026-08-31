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
package eu.jsentinel.jcustos.dx.runtime;

/**
 * Severity level of a {@link JSentinelBootstrapWarning}.
 * <p>
 * In {@code STRICT} mode, {@link #ERROR} entries are converted into a
 * {@code JSentinelBootstrapException}; {@link #WARNING} and {@link #INFO}
 * entries are attached to the resulting {@link JSentinelRuntime}.
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable.
 */
public enum Severity {
  INFO,
  WARNING,
  ERROR
}
