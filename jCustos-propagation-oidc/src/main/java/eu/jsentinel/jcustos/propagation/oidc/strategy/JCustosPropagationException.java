/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.oidc.strategy;


/**
 * Hard failure of a V00.74 outbound-token strategy — token endpoint
 * returned 4xx / 5xx, body was malformed, etc.
 *
 * <p>By contract, V00.74 strategies <strong>never</strong> swallow
 * such failures (Konzept §13.2 "no silent downgrade"). The wrapper
 * propagates the exception so the outbound call fails loudly.
 *
 * @since 00.74.00
 */
public class JCustosPropagationException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final int httpStatus;

  public JCustosPropagationException(int httpStatus, String message) {
    super(message);
    this.httpStatus = httpStatus;
  }

  public JCustosPropagationException(int httpStatus, String message, Throwable cause) {
    super(message, cause);
    this.httpStatus = httpStatus;
  }

  /** @return HTTP status received from the token endpoint (or 0 if pre-call) */
  public int httpStatus() {
    return httpStatus;
  }
}
