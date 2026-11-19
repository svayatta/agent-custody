// The door filter in front of a JDK HttpServer handler, over real sockets. DOOR_URL points at `agent-custody door`
// with "authz": true; CUSTODY_GRANT is a passport scoped to the refund route.
//   javac -d out *.java && java -Djdk.httpclient.allowRestrictedHeaders=host -cp out DoorExample
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class DoorExample {
    static final Map<String, String> seen = new HashMap<>();
    static final HttpClient http = HttpClient.newHttpClient();

    static HttpServer serve(CustodyDoor door) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            seen.put("ran", "yes");
            seen.put("receipt", ex.getRequestHeaders().getFirst(CustodyDoor.RECEIPT));
            seen.put("class", ex.getRequestHeaders().getFirst(CustodyDoor.CLASS));
            seen.put("grant", ex.getRequestHeaders().getFirst("X-Agent-Custody-Grant"));
            seen.put("body", new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] answer = "{\"shop\":\"answered\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, answer.length);
            ex.getResponseBody().write(answer);
            ex.close();
        }).getFilters().add(new CustodyDoorFilter(door));
        server.start();
        return server;
    }

    static HttpResponse<String> send(HttpServer server, String method, String target, String body, String... headers) throws Exception {
        seen.clear();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + target))
                .header("Host", "shop.example")
                .method(method, body.isEmpty() ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static void check(boolean ok, String msg) {
        if (!ok) {
            System.err.println("java: " + msg);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws Exception {
        String doorUrl = System.getenv("DOOR_URL"), grant = System.getenv("CUSTODY_GRANT");
        check(doorUrl != null && grant != null, "set DOOR_URL and CUSTODY_GRANT");
        HttpServer shop = serve(new CustodyDoor(URI.create(doorUrl), Duration.ofSeconds(5)));

        // 1. A public read: allowed, and the handler sees the door's receipt in place of the one the client forged.
        HttpResponse<String> res = send(shop, "GET", "/catalogue/shoes?colour=red", "", CustodyDoor.RECEIPT, "forged", "X-Forwarded-For", "198.51.100.66", "User-Agent", "example-browser");
        String receipt = seen.get("receipt");
        check(res.statusCode() == 200 && seen.containsKey("ran") && receipt != null && !receipt.equals("forged") && receipt.equals(res.headers().firstValue(CustodyDoor.RECEIPT).orElse("")) && "unknown".equals(seen.get("class")), "allowed read: " + res.statusCode() + " " + seen);
        System.out.println("java: GET /catalogue/shoes allowed, class " + seen.get("class"));
        System.out.println("receipt allowed " + receipt);

        // 2. An unknown arrival's refund: refused with the door's 403 and body; the handler never runs. The client's own
        // X-Original-* headers do not change what the door decides on.
        res = send(shop, "POST", "/refunds", "{\"amount\":1000}", "Content-Type", "application/json", "X-Original-Method", "GET", "X-Original-URI", "/catalogue/free");
        String denied = res.headers().firstValue(CustodyDoor.RECEIPT).orElse("");
        check(res.statusCode() == 403 && seen.isEmpty() && !denied.isEmpty() && res.body().contains("refused by the door's policy"), "refused refund: " + res.statusCode() + " " + res.body());
        System.out.println("java: POST /refunds refused 403");
        System.out.println("receipt denied " + denied);

        // 3. A verified agent's refund: allowed after the door committed it to the log; the handler gets the body, the
        // receipt, and the class, and never the grant.
        res = send(shop, "POST", "/refunds", "{\"amount\":1000}", "Content-Type", "application/json", "X-Agent-Custody-Grant", grant);
        receipt = seen.get("receipt");
        check(res.statusCode() == 200 && "verified".equals(seen.get("class")) && seen.get("grant") == null && "{\"amount\":1000}".equals(seen.get("body")) && receipt != null && receipt.equals(res.headers().firstValue(CustodyDoor.RECEIPT).orElse("")), "verified refund: " + res.statusCode() + " " + seen);
        System.out.println("java: POST /refunds with a passport allowed, class " + seen.get("class"));
        System.out.println("receipt verified " + receipt);
        shop.stop(0);

        // 4. A door that is down, and one that never answers: 503, and the handler never runs.
        int gonePort;
        try (ServerSocket gone = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
            gonePort = gone.getLocalPort();
        }
        HttpServer down = serve(new CustodyDoor(URI.create("http://127.0.0.1:" + gonePort), Duration.ofSeconds(2)));
        res = send(down, "GET", "/catalogue/shoes", "");
        down.stop(0);
        check(res.statusCode() == 503 && seen.isEmpty(), "unreachable door: " + res.statusCode());
        System.out.println("fail-closed unreachable " + res.statusCode());
        try (ServerSocket silent = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) { // accepts connections and never answers
            HttpServer stalled = serve(new CustodyDoor(URI.create("http://127.0.0.1:" + silent.getLocalPort()), Duration.ofMillis(500)));
            res = send(stalled, "GET", "/catalogue/shoes", "");
            stalled.stop(0);
        }
        check(res.statusCode() == 503 && seen.isEmpty(), "silent door: " + res.statusCode());
        System.out.println("fail-closed timeout " + res.statusCode());
        System.out.println("OK");
    }
}
