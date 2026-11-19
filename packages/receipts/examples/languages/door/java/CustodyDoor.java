// A client of an agent-custody door in authz mode ("authz": true): asks the door about one request, as nginx
// auth_request does. JDK only (java.net.http). CustodyDoorFilter wraps it for com.sun.net.httpserver; a Spring
// OncePerRequestFilter wraps it the same way (docs/door-languages.md).
//
// Start the JVM with -Djdk.httpclient.allowRestrictedHeaders=host: java.net.http refuses to send another Host, and
// the door checks a Web Bot Auth signature against the client's Host. The constructor refuses to start without it.
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class CustodyDoor {
    public static final String RECEIPT = "X-Agent-Custody-Receipt";
    public static final String CLASS = "X-Agent-Custody-Class";
    public static final String LOG_PENDING = "X-Agent-Custody-Log-Pending";
    /** The door's credentials: the door reads them, the application does not get them. */
    public static final List<String> DOOR_ONLY = List.of("X-Agent-Custody-Grant", "X-Agent-Custody-Agent");
    // Hop-by-hop and body fields stay off the check, which is its own GET with no body. The three the door decides on
    // are set here, never copied from the client.
    private static final Set<String> NOT_FORWARDED = Set.of("connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
            "upgrade", "content-length", "expect", "http2-settings", "x-original-method", "x-original-uri", "x-forwarded-for");

    /** The door's answer. {@code allowed} only on a 200 that carries a receipt; otherwise send status, body, and headers to the client. */
    public record Verdict(boolean allowed, int status, String contentType, byte[] body, Map<String, String> doorHeaders) {
        public String receipt() { return doorHeaders.get(RECEIPT); }
        public String arrivalClass() { return doorHeaders.getOrDefault(CLASS, ""); }
    }

    private final URI check;
    private final Duration timeout;
    private final HttpClient client;

    public CustodyDoor(URI door, Duration timeout) {
        try {
            HttpRequest.newBuilder().header("Host", "probe");
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("start the JVM with -Djdk.httpclient.allowRestrictedHeaders=host, so that the door sees the client's Host", e);
        }
        this.check = URI.create(door.toString().replaceAll("/+$", "") + "/_agent_custody");
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
    }

    /**
     * Asks the door about one request: its method, its raw path and query, its headers, and the address it came from.
     * A door that cannot be reached, does not answer within the timeout, or allows without a receipt gives a 503.
     */
    public Verdict check(String method, String rawPathAndQuery, Map<String, List<String>> headers, String remoteAddress) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(check).timeout(timeout).GET();
            boolean userAgent = false;
            for (Map.Entry<String, List<String>> h : headers.entrySet()) {
                String name = h.getKey().toLowerCase(Locale.ROOT);
                if (NOT_FORWARDED.contains(name)) continue;
                userAgent |= name.equals("user-agent");
                for (String v : h.getValue()) b.header(h.getKey(), v);
            }
            // java.net.http would send its own, and the receipt would record it as the client's; it cannot send none, so an empty one
            if (!userAgent) b.header("User-Agent", "");
            b.setHeader("X-Original-Method", method).setHeader("X-Original-URI", rawPathAndQuery).setHeader("X-Forwarded-For", remoteAddress);
            HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, String> door = new LinkedHashMap<>();
            for (String name : List.of(RECEIPT, CLASS, LOG_PENDING, "Retry-After")) res.headers().firstValue(name).ifPresent(v -> door.put(name, v));
            boolean receipt = door.containsKey(RECEIPT) && !door.get(RECEIPT).isEmpty();
            if (res.statusCode() == 200 && !receipt) return unavailable("the door allowed the request without a receipt");
            return new Verdict(res.statusCode() == 200, res.statusCode(), res.headers().firstValue("Content-Type").orElse(null), res.body(), door);
        } catch (IOException | IllegalArgumentException e) { // refused, timed out, reset, or a header value the client will not send
            return unavailable("the door could not be reached");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return unavailable("interrupted while asking the door");
        }
    }

    private static Verdict unavailable(String reason) {
        byte[] body = ("{\"error\":\"not passed on: " + reason + "\"}").getBytes(StandardCharsets.UTF_8);
        return new Verdict(false, 503, "application/json", body, Map.of());
    }
}
