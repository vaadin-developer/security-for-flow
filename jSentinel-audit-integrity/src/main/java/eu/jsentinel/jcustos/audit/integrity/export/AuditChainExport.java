package eu.jsentinel.jcustos.audit.integrity.export;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
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

import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.List;
import java.util.Objects;

/**
 * A verifiable export: the signed batch plus the chain range it covers.
 * Re-verification needs nothing but this object (or its NDJSON form) and
 * the public key material.
 *
 * @param batch   the signed statement
 * @param entries the covered range (immutable copy)
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public record AuditChainExport(SignedAuditBatch batch, List<AuditChainEntry> entries) {

  public AuditChainExport {
    Objects.requireNonNull(batch, "batch");
    entries = List.copyOf(Objects.requireNonNull(entries, "entries"));
  }
}
