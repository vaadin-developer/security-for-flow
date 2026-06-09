/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.abuse;

/**
 * Counter dimension used by {@link AbuseDetectionService}.
 *
 * <p>The Konzept §13 calls out a fixed set of axes; this enum names
 * them so policies and audit events stay structural and consistent.</p>
 */
public enum AbuseDimension {
  /** Per-username counter — defends against targeted brute force. */
  USERNAME,
  /** Per-client-address counter — defends against client-level abuse. */
  CLIENT_ADDRESS,
  /** Per-tenant counter — protects a shared customer slice. */
  TENANT,
  /** Process-wide counter — last-resort global ceiling. */
  GLOBAL
}
