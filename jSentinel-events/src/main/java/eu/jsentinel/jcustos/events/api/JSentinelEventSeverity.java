package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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
 * Security-relevance level of a {@link JSentinelEvent} for monitoring,
 * alerting and incident handling.
 *
 * <p>Severity is <em>not</em> a logging-level replacement (Konzept §211). It
 * expresses how relevant the event is from a security standpoint, ordered
 * from least to most relevant.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public enum JSentinelEventSeverity {

  /** Diagnostic detail, normally not surfaced to monitoring. */
  DEBUG,

  /** Routine, expected security event. */
  INFO,

  /** Noteworthy but not yet concerning. */
  NOTICE,

  /** Potentially concerning; warrants attention. */
  WARNING,

  /** A security-relevant failure occurred. */
  ERROR,

  /** Severe security incident requiring immediate handling. */
  CRITICAL
}
