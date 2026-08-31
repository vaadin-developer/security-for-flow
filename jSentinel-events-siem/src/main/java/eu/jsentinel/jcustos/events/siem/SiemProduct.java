package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jSentinel Events — SIEM exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * The one home of the vendor/product identity every SIEM record header
 * carries (CEF and LEEF headers share it).
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class SiemProduct {

  /** Device vendor field of the CEF/LEEF headers. */
  public static final String VENDOR = "svenruppert";
  /** Device product field of the CEF/LEEF headers. */
  public static final String PRODUCT = "jSentinel";
  /**
   * Device version field — the jar's implementation version, or
   * {@code "unknown"} when running from an exploded classpath (tests, IDE).
   */
  public static final String VERSION = resolveVersion();

  private SiemProduct() {
  }

  private static String resolveVersion() {
    Package pkg = SiemProduct.class.getPackage();
    String version = pkg == null ? null : pkg.getImplementationVersion();
    return version == null || version.isBlank() ? "unknown" : version;
  }
}
