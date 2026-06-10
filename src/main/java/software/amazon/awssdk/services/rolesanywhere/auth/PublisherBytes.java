package software.amazon.awssdk.services.rolesanywhere.auth;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/**
 * Utility class for converting between byte arrays and reactive
 * {@link Publisher Publisher&lt;ByteBuffer&gt;} streams.
 *
 * <p>Provides two complementary operations:
 * <ul>
 *   <li>{@link #collect(Publisher)} — consumes a publisher and returns the concatenated bytes</li>
 *   <li>{@link #toPublisher(byte[])} — wraps a byte array into a single-element publisher</li>
 * </ul>
 */
final class PublisherBytes {

    private static final long COLLECT_TIMEOUT_SECONDS = 30;

    private PublisherBytes() {}

    /**
     * Subscribe to the publisher, collect every emitted {@link ByteBuffer},
     * and return the concatenated bytes. Blocks until onComplete or onError.
     */
    static byte[] collect(Publisher<ByteBuffer> publisher) {
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
        try {
            return future.get(COLLECT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            future.completeExceptionally(e);
            cancelSubscription(subscriptionRef);
            Thread.currentThread().interrupt();
            throw new RuntimeException("Failed to collect async payload bytes", e);
        } catch (ExecutionException e) {
            cancelSubscription(subscriptionRef);
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new RuntimeException("Failed to collect async payload bytes", cause);
        } catch (Exception e) {
            future.completeExceptionally(e);
            cancelSubscription(subscriptionRef);
            throw new RuntimeException("Failed to collect async payload bytes", e);
        }
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
