import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class FakeWebLoginServer {
    private static final int PORT = 8080;
    private static final String LOG_FILE = "logs/auth.log";

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", FakeWebLoginServer::handleRequest);
        server.setExecutor(null);
        System.out.println("Fake Web Admin Honeypot running on http://localhost:" + PORT);
        server.start();
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();

        // Extract real public IP passed by Tailscale Funnel via X-Forwarded-For
        String forwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        String clientIp = (forwardedFor != null && !forwardedFor.isBlank())
                ? forwardedFor.split(",")[0].trim()
                : exchange.getRemoteAddress().getAddress().getHostAddress();

        String message = "";

        if ("POST".equalsIgnoreCase(method)) {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractFormParam(body, "username");
            if (username.isBlank()) username = "admin";

            logFailedAttempt(username, clientIp, exchange.getRemoteAddress().getPort());
            message = "<p style='color:red;'>Access Denied: Invalid credentials for user '" + username + "'.</p>";
        }

        String html = "<!DOCTYPE html><html><body style='font-family:sans-serif;max-width:400px;margin:60px auto;'>"
                + "<h2>Server Admin Portal</h2>"
                + message
                + "<form method='POST' action='/'>"
                + "Username:<br><input type='text' name='username' value='root' style='width:100%;padding:8px;margin:6px 0;'><br>"
                + "Password:<br><input type='password' name='password' style='width:100%;padding:8px;margin:6px 0;'><br>"
                + "<button type='submit' style='padding:10px 20px;margin-top:8px;'>Login</button>"
                + "</form></body></html>";

        byte[] responseBytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    private static String extractFormParam(String body, String key) {
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) {
                return URLDecoder.decode(kv[1], StandardCharsets.UTF_8).replaceAll("[^a-zA-Z0-9._-]", "");
            }
        }
        return "";
    }

    private static synchronized void logFailedAttempt(String user, String ip, int port) {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH);
        String timestamp = LocalDateTime.now().format(fmt);
        String logLine = String.format("%s prod-web-01 sshd: Failed password for %s from %s port %d ssh2%n",
                timestamp, user, ip, port);

        try {
            Path path = Path.of(LOG_FILE);
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            Files.writeString(path, logLine, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.out.print("Logged: " + logLine);
        } catch (IOException e) {
            System.err.println("Failed to write log: " + e.getMessage());
        }
    }
}
