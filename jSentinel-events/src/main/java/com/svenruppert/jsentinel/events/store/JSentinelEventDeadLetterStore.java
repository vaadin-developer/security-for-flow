package com.svenruppert.jsentinel.events.store;

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

import java.util.List;

/**
 * Dead-letter store (Konzept §736): keeps structured records of envelopes that
 * failed verification, replay, sequence or producer-policy checks, for later
 * inspection and resolution.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventDeadLetterStore {

  /**
   * Stores a dead-letter record.
   *
   * @param deadLetter the record
   */
  void store(JSentinelEventDeadLetter deadLetter);

  /**
   * @param limit the maximum number of records to return
   * @return up to {@code limit} unresolved dead letters, oldest first
   */
  List<JSentinelEventDeadLetter> findOpen(int limit);

  /**
   * Marks a dead letter resolved so it no longer appears in {@link
   * #findOpen(int)}.
   *
   * @param id the dead-letter identity
   */
  void markResolved(DeadLetterId id);
}
