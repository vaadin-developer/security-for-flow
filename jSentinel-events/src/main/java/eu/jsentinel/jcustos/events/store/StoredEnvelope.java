package eu.jsentinel.jcustos.events.store;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.util.Objects;

/**
 * An envelope together with its stable store position, returned by
 * {@link JCustosEventEnvelopeStore#findAfter(JCustosEventCursor, int)} so a
 * consumer can advance its {@link JCustosEventCursor} for the next page.
 *
 * @param cursor the position of this envelope in the store's append order
 * @param envelope the stored envelope
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record StoredEnvelope(JCustosEventCursor cursor, SignedJCustosEventEnvelope envelope) {

  public StoredEnvelope {
    Objects.requireNonNull(cursor, "cursor");
    Objects.requireNonNull(envelope, "envelope");
  }
}
