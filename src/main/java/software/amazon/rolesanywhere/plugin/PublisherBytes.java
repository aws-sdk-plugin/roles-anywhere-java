package software.amazon.rolesanywhere.plugin;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.annotations.SdkInternalApi;

/**
 * Utility class for converting between byte arrays and reactive
 * {@link Publisher Publisher&lt;ByteBuffer&gt;} streams.
 *
 * <p>Provides two complementary operations:
 * <ul>
 *   <li>{@link #collectAsync(Publisher)} — subscribes and returns a future that
 *       completes with the concatenated bytes when the publisher does</li>
 *   <li>{@link #toPublisher(byte[])} — wraps a byte array into a single-element publisher</li>
 * </ul>
 */
@SdkInternalApi
final class PublisherBytes {

    private PublisherBytes() {}

    /**
     * Subscribe to the publisher and return a {@link CompletableFuture} that
     * completes with the concatenated bytes when the publisher signals
     * {@code onComplete}, or completes exceptionally on {@code onError}. Does
     * not block — the caller composes on the returned future (via
     * {@code thenApply} / {@code thenCompose}).
     */
    static CompletableFuture<byte[]> collectAsync(Publisher<ByteBuffer> publisher) {
        CompletableFuture<byte[]> future = new CompletableFuture<>();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        AtomicReference<Subscription> subscriptionRef = new AtomicReference<>();
        publisher.subscribe(new Subscriber<>() {

            @Override
            public void onSubscribe(Subscription s) {
                subscriptionRef.set(s);
                if (future.isDone()) {
                    cancelSubscription(subscriptionRef);
                } else {
                    s.request(Long.MAX_VALUE);
                }
            }

            @Override
            public void onNext(ByteBuffer byteBuffer) {
                try {
                    byte[] bytes = new byte[byteBuffer.remaining()];
                    byteBuffer.get(bytes);
                    buffer.write(bytes, 0, bytes.length);
                } catch (Throwable t) {
                    cancelSubscription(subscriptionRef);
                    future.completeExceptionally(t);
                }
            }

            @Override
            public void onError(Throwable t) {
                future.completeExceptionally(t);
            }

            @Override
            public void onComplete() {
                future.complete(buffer.toByteArray());
            }
        });
        return future;
    }

    /**
     * Wraps a byte array into a single-element reactive {@link Publisher Publisher&lt;ByteBuffer&gt;}
     * that emits one {@link ByteBuffer} containing the given bytes, then completes.
     *
     * <p>The returned publisher is compliant with the Reactive Streams specification:
     * <ul>
     *   <li>§1.2 — at most one element is delivered (enforced via {@link AtomicBoolean#compareAndSet})</li>
     *   <li>§1.7 — no signals occur after a terminal signal</li>
     *   <li>§3.9 — {@code request(n)} with {@code n <= 0} signals {@code onError}</li>
     * </ul>
     */
    static Publisher<ByteBuffer> toPublisher(byte[] bytes) {
        return subscriber -> subscriber.onSubscribe(new Subscription() {
            private volatile boolean cancelled;
            private final AtomicBoolean sent = new AtomicBoolean();

            @Override
            public void request(long n) {
                if (cancelled || !sent.compareAndSet(false, true)) {
                    return;
                }
                if (n <= 0) {
                    cancelled = true;
                    subscriber.onError(new IllegalArgumentException("§3.9: request amount must be > 0, was " + n));
                    return;
                }
                subscriber.onNext(ByteBuffer.wrap(bytes));
                if (!cancelled) {
                    subscriber.onComplete();
                }
            }

            @Override
            public void cancel() {
                cancelled = true;
            }
        });
    }

    private static void cancelSubscription(AtomicReference<Subscription> subscriptionRef) {
        Subscription s = subscriptionRef.getAndSet(null);
        if (s != null) {
            s.cancel();
        }
    }
}
