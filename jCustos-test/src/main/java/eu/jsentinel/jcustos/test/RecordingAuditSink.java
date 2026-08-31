/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Captures every published {@link AuditEvent} into a list for later
 * inspection. Use the typed accessors {@link #single(Class)} /
 * {@link #all(Class)} to assert on specific event types without
 * casting.
 */
public final class RecordingAuditSink implements JCustosAuditService {

  private final List<AuditEvent> events = new ArrayList<>();

  /** Creates an empty recording sink. */
  public RecordingAuditSink() {
  }

  @Override
  public void publish(AuditEvent event) {
    events.add(event);
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    return Collections.unmodifiableList(events);
  }

  /**
   * Returns every recorded event in publication order.
   *
   * @return read-only view of all events
   */
  public List<AuditEvent> events() {
    return Collections.unmodifiableList(events);
  }

  /**
   * Returns every recorded event of the given type, in publication
   * order.
   *
   * @param type event type filter
   * @param <T>  event type
   * @return read-only list of matching events
   */
  public <T extends AuditEvent> List<T> all(Class<T> type) {
    return events.stream()
        .filter(type::isInstance)
        .map(type::cast)
        .toList();
  }

  /**
   * Returns the single event of the given type. Throws an
   * {@link AssertionError} when zero or more than one event of that
   * type was recorded.
   *
   * @param type event type filter
   * @param <T>  event type
   * @return the matching event
   */
  public <T extends AuditEvent> T single(Class<T> type) {
    List<T> matching = all(type);
    if (matching.size() != 1) {
      throw new AssertionError(
          "expected exactly one " + type.getSimpleName()
              + " event, got " + matching.size() + "; recorded: " + events);
    }
    return matching.getFirst();
  }

  /** Drops every recorded event. */
  public void clear() {
    events.clear();
  }
}
