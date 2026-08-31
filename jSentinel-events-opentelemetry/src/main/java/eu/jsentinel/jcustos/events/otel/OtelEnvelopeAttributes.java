package eu.jsentinel.jcustos.events.otel;

/*-
 * #%L
 * jCustos Events — OpenTelemetry exporter
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
import io.opentelemetry.api.common.AttributeKey;

/**
 * The OpenTelemetry attribute vocabulary of the jCustos envelope-to-log
 * mapping. Attribute names are API — renaming one is a breaking change for
 * every dashboard and alert rule built on them.
 * <p>
 * Data minimization: the vocabulary deliberately contains <strong>no
 * payload and no signature attribute</strong>. The
 * {@link #PAYLOAD_HASH} is the verifiable reference to the payload; the
 * full signed record travels over the webhook/REST integrations, not
 * through telemetry.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class OtelEnvelopeAttributes {

  /** Instrumentation scope the publisher registers under. */
  public static final String INSTRUMENTATION_SCOPE = "eu.jsentinel.jcustos.events";

  public static final AttributeKey<String> ENVELOPE_ID =
      AttributeKey.stringKey("jsentinel.envelope.id");
  public static final AttributeKey<String> EVENT_ID =
      AttributeKey.stringKey("jsentinel.event.id");
  public static final AttributeKey<String> EVENT_TYPE =
      AttributeKey.stringKey("jsentinel.event.type");
  public static final AttributeKey<String> TENANT_ID =
      AttributeKey.stringKey("jsentinel.tenant.id");
  public static final AttributeKey<String> SUBJECT_ID =
      AttributeKey.stringKey("jsentinel.subject.id");
  public static final AttributeKey<String> PRODUCER_ID =
      AttributeKey.stringKey("jsentinel.producer.id");
  public static final AttributeKey<Long> SEQUENCE =
      AttributeKey.longKey("jsentinel.sequence");
  public static final AttributeKey<String> CORRELATION_ID =
      AttributeKey.stringKey("jsentinel.correlation.id");
  public static final AttributeKey<String> CAUSATION_ID =
      AttributeKey.stringKey("jsentinel.causation.id");
  public static final AttributeKey<String> KEY_ID =
      AttributeKey.stringKey("jsentinel.key.id");
  public static final AttributeKey<String> SIGNATURE_ALGORITHM =
      AttributeKey.stringKey("jsentinel.signature.algorithm");
  public static final AttributeKey<String> PAYLOAD_CONTENT_TYPE =
      AttributeKey.stringKey("jsentinel.payload.content_type");
  public static final AttributeKey<String> PAYLOAD_HASH_ALGORITHM =
      AttributeKey.stringKey("jsentinel.payload.hash_algorithm");
  public static final AttributeKey<String> PAYLOAD_HASH =
      AttributeKey.stringKey("jsentinel.payload.hash");

  private OtelEnvelopeAttributes() {
  }
}
