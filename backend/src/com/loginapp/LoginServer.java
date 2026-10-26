package com.loginapp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class LoginServer {
    private static final int PORT = 8080;
    private static final Map<String, User> USERS = new HashMap<>();
    private static final Map<String, Long> REVOKED_TOKENS = new ConcurrentHashMap<>();
    private static final JwtService JWT = new JwtService(jwtSecret());

    public static void main(String[] args) throws IOException {
        USERS.put("admin", new User("admin", "admin123", "Admin User"));
        USERS.put("keerthi", new User("keerthi", "password", "Katuri"));

        Path frontendDir = resolveFrontendDir();
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/api/login", LoginServer::handleLogin);
        server.createContext("/api/logout", LoginServer::handleLogout);
        server.createContext("/api/me", LoginServer::handleMe);
        server.createContext("/", exchange -> serveStatic(exchange, frontendDir));
        server.setExecutor(null);
        server.start();

        System.out.println("Login app running at http://localhost:" + PORT);
        System.out.println("JWT HS256 enabled. Tokens expire after " + (JwtService.ttlSeconds() / 60) + " minutes.");
        System.out.println("Demo accounts:");
        System.out.println("  admin / admin123");
        System.out.println("  keerthi / password");
        System.out.println("Frontend folder: " + frontendDir.toAbsolutePath());
    }

    private static String jwtSecret() {
        String fromEnv = System.getenv("JWT_SECRET");
        if (fromEnv != null && fromEnv.length() >= 32) {
            return fromEnv;
        }
        return "local-dev-only-change-me-32chars!!";
    }

    private static Path resolveFrontendDir() {
        Path cwd = Paths.get("").toAbsolutePath();
        Path[] candidates = {
                cwd.resolve("frontend"),
                cwd.getParent() != null ? cwd.getParent().resolve("frontend") : null,
                cwd.resolve("github-fork-practice1").resolve("frontend")
        };
        for (Path candidate : candidates) {
            if (candidate != null && Files.isRegularFile(candidate.resolve("index.html"))) {
                return candidate;
            }
        }
        return cwd.resolve("frontend");
    }

    private static void handleLogin(HttpExchange exchange) throws IOException {
        if (preflight(exchange)) {
            return;
        }
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"ok\":false,\"message\":\"Method not allowed\"}");
            return;
        }

        String body = readBody(exchange);
        String username = jsonString(body, "username");
        String password = jsonString(body, "password");

        if (username == null || password == null || username.isBlank() || password.isBlank()) {
            sendJson(exchange, 400, "{\"ok\":false,\"message\":\"Username and password are required\"}");
            return;
        }

        User user = USERS.get(username.toLowerCase());
        if (user == null || !passwordsMatch(user.password, password)) {
            sendJson(exchange, 401, "{\"ok\":false,\"message\":\"Invalid username or password\"}");
            return;
        }

        String token = JWT.issue(user.username, user.displayName);
        String json = "{\"ok\":true,\"message\":\"Login successful\",\"tokenType\":\"Bearer\",\"expiresIn\":"
                + JwtService.ttlSeconds()
                + ",\"token\":\"" + escape(token)
                + "\",\"user\":{\"username\":\"" + escape(user.username)
                + "\",\"displayName\":\"" + escape(user.displayName) + "\"}}";
        sendJson(exchange, 200, json);
    }

    private static void handleLogout(HttpExchange exchange) throws IOException {
        if (preflight(exchange)) {
            return;
        }
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"ok\":false,\"message\":\"Method not allowed\"}");
            return;
        }
        try {
            JwtService.Claims claims = requireJwt(exchange);
            REVOKED_TOKENS.put(claims.jti(), claims.expiresAt());
            pruneRevoked();
            sendJson(exchange, 200, "{\"ok\":true,\"message\":\"Logged out\"}");
        } catch (IllegalArgumentException ex) {
            sendJson(exchange, 401, "{\"ok\":false,\"message\":\"" + escape(ex.getMessage()) + "\"}");
        }
    }

    private static void handleMe(HttpExchange exchange) throws IOException {
        if (preflight(exchange)) {
            return;
        }
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"ok\":false,\"message\":\"Method not allowed\"}");
            return;
        }
        try {
            JwtService.Claims claims = requireJwt(exchange);
            User user = USERS.get(claims.username());
            String displayName = user != null ? user.displayName : claims.displayName();
            String json = "{\"ok\":true,\"user\":{\"username\":\"" + escape(claims.username())
                    + "\",\"displayName\":\"" + escape(displayName) + "\"}}";
            sendJson(exchange, 200, json);
        } catch (IllegalArgumentException ex) {
            sendJson(exchange, 401, "{\"ok\":false,\"message\":\"" + escape(ex.getMessage()) + "\"}");
        }
    }

    private static JwtService.Claims requireJwt(HttpExchange exchange) {
        JwtService.Claims claims = JWT.verify(bearerToken(exchange));
        pruneRevoked();
        if (REVOKED_TOKENS.containsKey(claims.jti())) {
            throw new IllegalArgumentException("JWT revoked");
        }
        return claims;
    }

    private static void pruneRevoked() {
        long now = Instant.now().getEpochSecond();
        Iterator<Map.Entry<String, Long>> iterator = REVOKED_TOKENS.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            if (entry.getValue() <= now) {
                iterator.remove();
            }
        }
    }

    private static boolean passwordsMatch(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static void serveStatic(HttpExchange exchange, Path frontendDir) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())
                && !"HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"ok\":false,\"message\":\"Method not allowed\"}");
            return;
        }

        String rawPath = exchange.getRequestURI().getPath();
        if (rawPath == null || rawPath.isBlank() || "/".equals(rawPath)) {
            rawPath = "/index.html";
        }
        Path requested = frontendDir.resolve(rawPath.substring(1)).normalize();
        if (!requested.startsWith(frontendDir.toAbsolutePath().normalize()) || !Files.isRegularFile(requested)) {
            requested = frontendDir.resolve("index.html");
        }
        if (!Files.isRegularFile(requested)) {
            byte[] notFound = "Frontend not found. Run the server from the project root.".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, notFound.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(notFound);
            }
            return;
        }

        byte[] bytes = Files.readAllBytes(requested);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType(requested.getFileName().toString()));
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static boolean preflight(HttpExchange exchange) throws IOException {
        addCors(exchange);
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return true;
        }
        return false;
    }

    private static void addCors(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        addCors(exchange);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String bearerToken(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring("Bearer ".length()).trim();
    }

    private static String jsonString(String json, String key) {
        if (json == null) {
            return null;
        }
        String pattern = "\"" + key + "\"";
        int keyIndex = json.indexOf(pattern);
        if (keyIndex < 0) {
            return null;
        }
        int colon = json.indexOf(':', keyIndex + pattern.length());
        if (colon < 0) {
            return null;
        }
        int firstQuote = json.indexOf('"', colon + 1);
        if (firstQuote < 0) {
            return null;
        }
        int secondQuote = json.indexOf('"', firstQuote + 1);
        if (secondQuote < 0) {
            return null;
        }
        return json.substring(firstQuote + 1, secondQuote);
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String contentType(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".html")) {
            return "text/html; charset=utf-8";
        }
        if (lower.endsWith(".css")) {
            return "text/css; charset=utf-8";
        }
        if (lower.endsWith(".js") || lower.endsWith(".jsx")) {
            return "text/javascript; charset=utf-8";
        }
        if (lower.endsWith(".svg")) {
            return "image/svg+xml";
        }
        return "application/octet-stream";
    }

    private static final class User {
        final String username;
        final String password;
        final String displayName;

        User(String username, String password, String displayName) {
            this.username = username;
            this.password = password;
            this.displayName = displayName;
        }
    }
}
