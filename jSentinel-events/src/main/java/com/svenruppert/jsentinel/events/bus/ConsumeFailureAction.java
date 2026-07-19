package com.svenruppert.jsentinel.events.bus;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * What happens to an envelope that failed consume-side verification
 * (Konzept goal 10 subset, V00.80.00). Every failure is ALWAYS a reject
 * toward the producer — the action only decides whether a forensic
 * dead-letter record is additionally kept for operator review.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public enum ConsumeFailureAction {

  /** Reject only — no attacker-controlled bytes are retained (fail-closed). */
  REJECT,

  /** Reject AND keep the envelope as a dead letter for operator review. */
  REJECT_AND_DEAD_LETTER
}
