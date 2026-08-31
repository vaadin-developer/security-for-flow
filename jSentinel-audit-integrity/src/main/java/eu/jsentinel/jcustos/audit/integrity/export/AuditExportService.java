package eu.jsentinel.jcustos.audit.integrity.export;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainException;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads a chain range from the store and signs it into a verifiable
 * {@link AuditChainExport} (Konzept goal 7: "verifizierbare Exporte").
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class AuditExportService {

  static final String CODE_EXPORT_RANGE = "audit-integrity/export-range";
  private static final int PAGE_SIZE = 512;

  private final AuditChainStore store;
  private final AuditBatchSigner signer;

  public AuditExportService(AuditChainStore store, AuditBatchSigner signer) {
    this.store = Objects.requireNonNull(store, "store");
    this.signer = Objects.requireNonNull(signer, "signer");
  }

  /**
   * @param fromIndex first index to export
   * @param toIndex   last index to export (inclusive)
   * @return the signed export
   * @throws AuditChainException code {@code audit-integrity/export-range}
   *     when the range is invalid or not fully present in the store
   */
  public AuditChainExport exportRange(long fromIndex, long toIndex) {
    if (fromIndex < 0 || toIndex < fromIndex) {
      throw new AuditChainException(CODE_EXPORT_RANGE,
          "invalid range [" + fromIndex + ", " + toIndex + "]");
    }
    List<AuditChainEntry> entries = new ArrayList<>();
    long cursor = fromIndex;
    while (cursor <= toIndex) {
      int page = (int) Math.min(PAGE_SIZE, toIndex - cursor + 1);
      List<AuditChainEntry> read = store.read(cursor, page);
      if (read.isEmpty()) {
        break;
      }
      entries.addAll(read);
      cursor += read.size();
    }
    if (entries.size() != toIndex - fromIndex + 1) {
      throw new AuditChainException(CODE_EXPORT_RANGE,
          "range [" + fromIndex + ", " + toIndex + "] is not fully present"
              + " (found " + entries.size() + " entries)");
    }
    return new AuditChainExport(signer.sign(entries), entries);
  }

  /** @return the full chain as a signed export, or empty for a virgin chain */
  public Optional<AuditChainExport> exportAll() {
    long size = store.size();
    return size == 0
        ? Optional.empty()
        : Optional.of(exportRange(0, size - 1));
  }
}
