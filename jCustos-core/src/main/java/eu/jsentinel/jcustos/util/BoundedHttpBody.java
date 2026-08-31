package eu.jsentinel.jcustos.util;

import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscribers;

/**
 * Reads an HTTP response body under both a size and a time bound (CWE-400).
 *
 * <p>The obvious pattern hides a gap:
 *
 * <pre>{@code
 * var response = http.send(request, BodyHandlers.ofInputStream());  // timeout ends here
 * byte[] body = response.body().readNBytes(MAX + 1);                // unbounded in time
 * }</pre>
 *
 * <p>{@code HttpRequest.timeout(...)} covers the exchange up to the response
 * headers. With {@code ofInputStream()}, {@code send} returns at that point and
 * the body is read afterwards — outside the timeout. A server that answers the
 * headers promptly and then trickles the body one byte at a time holds the
 * calling thread indefinitely, which is a slow-loris on the client side. The
 * size cap does not help: the bytes do arrive, just never quickly.
 *
 * <p>Handing a fully-materialising subscriber to {@code send} closes it. The
 * call now returns only once the body is complete, so the request timeout
 * bounds the whole exchange, while {@link BodySubscribers#limiting} keeps the
 * size cap. An oversized body fails the request rather than filling the heap.
 *
 * @since 00.82.00
 */
public final class BoundedHttpBody {

  private BoundedHttpBody() {
  }

  /**
   * A body handler that materialises at most {@code maxBytes} and lets the
   * request timeout apply to the body transfer.
   *
   * <p>Exceeding the limit completes the request exceptionally — callers see it
   * as a failed exchange, not as a truncated body, so no caller can mistake a
   * cut-off response for a complete one.
   *
   * @param maxBytes hard ceiling for the body, must be positive
   * @return a handler producing the body as a byte array
   */
  public static BodyHandler<byte[]> ofByteArray(int maxBytes) {
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxBytes must be positive, was " + maxBytes);
    }
    return responseInfo -> BodySubscribers.limiting(
        HttpResponse.BodySubscribers.ofByteArray(), maxBytes);
  }
}
