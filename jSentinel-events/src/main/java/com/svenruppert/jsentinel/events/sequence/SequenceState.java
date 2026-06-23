package com.svenruppert.jsentinel.events.sequence;

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
 * Classification of an incoming sequence relative to the last accepted one
 * (Konzept §659).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public enum SequenceState {

  /** Exactly the next expected sequence (or the first one in the scope). */
  IN_ORDER,

  /** Higher than expected — one or more sequences were skipped. */
  GAP,

  /** Equal to a sequence already accepted — a repeat. */
  DUPLICATE,

  /** Lower than the last accepted sequence — a roll-back. */
  ROLLBACK
}
