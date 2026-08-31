package eu.jsentinel.jcustos.audit.integrity.chain;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * Failure of a chain operation, carrying a stable operator-facing code with
 * the {@code audit-integrity/} prefix so runbooks and alerts can route on
 * it. The message never contains payload bytes.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditChainException extends RuntimeException {

  private final String code;

  public AuditChainException(String code, String message) {
    super(code + ": " + message);
    this.code = Objects.requireNonNull(code, "code");
  }

  public AuditChainException(String code, String message, Throwable cause) {
    super(code + ": " + message, cause);
    this.code = Objects.requireNonNull(code, "code");
  }

  /** @return the stable {@code audit-integrity/...} code */
  public String code() {
    return code;
  }
}
