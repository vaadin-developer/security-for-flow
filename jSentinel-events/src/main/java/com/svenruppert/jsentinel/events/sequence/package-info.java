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

/**
 * V00.75 sequence-tracking SPI (Konzept §650-§674): the {@link
 * com.svenruppert.jsentinel.events.sequence.JSentinelEventSequenceStore}
 * (last monotone sequence per {@code tenantId + producerId}) with an in-memory
 * default, the {@link
 * com.svenruppert.jsentinel.events.sequence.SequenceViolationStrategy}, and a
 * pure {@link com.svenruppert.jsentinel.events.sequence.SequenceValidator} that
 * classifies an incoming sequence ({@code IN_ORDER} / {@code GAP} /
 * {@code DUPLICATE} / {@code ROLLBACK}) and maps it to a {@link
 * com.svenruppert.jsentinel.events.sequence.SequenceDecision}.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.sequence;
