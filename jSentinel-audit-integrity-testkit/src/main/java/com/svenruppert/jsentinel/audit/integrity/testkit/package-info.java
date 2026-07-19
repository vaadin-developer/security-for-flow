/*-
 * #%L
 * jSentinel Audit Integrity — contract testkit
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

/**
 * V00.80.00 (Konzept goal 7) contract testkit for the audit hash chain:
 * {@link com.svenruppert.jsentinel.audit.integrity.testkit.AuditChainStoreContract}
 * is the reusable {@code @Test}-default suite every
 * {@code AuditChainStore} implementation runs, and
 * {@link com.svenruppert.jsentinel.audit.integrity.testkit.TestkitChainEntries}
 * provides correctly-hashed deterministic chain fixtures plus tamper
 * helpers for verifier tests.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.audit.integrity.testkit;
