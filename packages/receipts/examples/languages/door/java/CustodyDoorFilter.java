// The door in front of a com.sun.net.httpserver.HttpServer context: context.getFilters().add(new CustodyDoorFilter(door)).
// JDK only. A refused request is answered with the door's status and body and never reaches the handler; an allowed
// one reaches it with the door's receipt and class in its headers and without the grant.
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;

public final class CustodyDoorFilter extends Filter {
    private final CustodyDoor door;

    public CustodyDoorFilter(CustodyDoor door) {
        this.door = door;
    }

    @Override
    public String description() {
        return "agent-custody door";
    }

    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        URI uri = exchange.getRequestURI();
        String target = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        CustodyDoor.Verdict v = door.check(exchange.getRequestMethod(), target, exchange.getRequestHeaders(), exchange.getRemoteAddress().getAddress().getHostAddress());
        v.doorHeaders().forEach((k, val) -> exchange.getResponseHeaders().set(k, val));
        if (!v.allowed()) {
            if (v.contentType() != null) exchange.getResponseHeaders().set("Content-Type", v.contentType());
            exchange.sendResponseHeaders(v.status(), v.body().length == 0 ? -1 : v.body().length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(v.body());
            }
            return;
        }
        // the server's request headers are read-only, so the handler gets a copy through a wrapping exchange
        Headers request = new Headers(exchange.getRequestHeaders());
        CustodyDoor.DOOR_ONLY.forEach(request::remove);
        request.set(CustodyDoor.RECEIPT, v.receipt());
        request.set(CustodyDoor.CLASS, v.arrivalClass());
        chain.doFilter(new Admitted(exchange, request));
    }

    private static final class Admitted extends HttpExchange {
        private final HttpExchange inner;
        private final Headers request;

        Admitted(HttpExchange inner, Headers request) {
            this.inner = inner;
            this.request = request;
        }

        @Override public Headers getRequestHeaders() { return request; }
        @Override public Headers getResponseHeaders() { return inner.getResponseHeaders(); }
        @Override public URI getRequestURI() { return inner.getRequestURI(); }
        @Override public String getRequestMethod() { return inner.getRequestMethod(); }
        @Override public HttpContext getHttpContext() { return inner.getHttpContext(); }
        @Override public void close() { inner.close(); }
        @Override public InputStream getRequestBody() { return inner.getRequestBody(); }
        @Override public OutputStream getResponseBody() { return inner.getResponseBody(); }
        @Override public void sendResponseHeaders(int code, long length) throws IOException { inner.sendResponseHeaders(code, length); }
        @Override public InetSocketAddress getRemoteAddress() { return inner.getRemoteAddress(); }
        @Override public int getResponseCode() { return inner.getResponseCode(); }
        @Override public InetSocketAddress getLocalAddress() { return inner.getLocalAddress(); }
        @Override public String getProtocol() { return inner.getProtocol(); }
        @Override public Object getAttribute(String name) { return inner.getAttribute(name); }
        @Override public void setAttribute(String name, Object value) { inner.setAttribute(name, value); }
        @Override public void setStreams(InputStream i, OutputStream o) { inner.setStreams(i, o); }
        @Override public HttpPrincipal getPrincipal() { return inner.getPrincipal(); }
    }
}
