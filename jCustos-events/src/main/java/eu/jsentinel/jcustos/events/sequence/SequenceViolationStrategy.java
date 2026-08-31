package eu.jsentinel.jcustos.events.sequence;

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

/**
 * How strictly sequence violations are handled (Konzept §667). For
 * {@code SIGNED_STRICT}, {@link #REJECT} is the default (Konzept §674).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public enum SequenceViolationStrategy {

  /** Reject the envelope outright. */
  REJECT,

  /** Route the envelope to the dead-letter store. */
  DEAD_LETTER,

  /** Accept the envelope but emit a warning. */
  ACCEPT_WITH_WARNING
}
