package com.loginapp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

final class JwtService {
    private static final long TTL_SECONDS = 15 * 60;
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final byte[] secret;

    JwtService(String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    String issue(String username, String displayName) {
        long now = Instant.now().getEpochSecond();
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"" + escape(username)
                + "\",\"name\":\"" + escape(displayName)
                + "\",\"jti\":\"" + UUID.randomUUID()
                + "\",\"iat\":" + now
                + ",\"exp\":" + (now + TTL_SECONDS) + "}";
        String signingInput = base64Url(header) + "." + base64Url(payload);
        return signingInput + "." + base64Url(hmac(signingInput));
    }

    Claims verify(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Missing token");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Malformed JWT");
        }

        String headerJson = decode(parts[0]);
        String alg = jsonString(headerJson, "alg");
        if (!"HS256".equals(alg)) {
            throw new IllegalArgumentException("Unsupported JWT algorithm");
        }

        String signingInput = parts[0] + "." + parts[1];
        byte[] expected = hmac(signingInput);
        byte[] actual = URL_DECODER.decode(parts[2]);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new IllegalArgumentException("Invalid JWT signature");
        }

        String payload = decode(parts[1]);
        String subject = jsonString(payload, "sub");
        String name = jsonString(payload, "name");
        String jti = jsonString(payload, "jti");
        Long exp = jsonLong(payload, "exp");
        if (subject == null || subject.isBlank() || exp == null) {
            throw new IllegalArgumentException("Invalid JWT claims");
        }
        if (Instant.now().getEpochSecond() >= exp) {
            throw new IllegalArgumentException("JWT expired");
        }
        return new Claims(subject, name == null ? subject : name, jti == null ? "" : jti, exp);
    }

    static long ttlSeconds() {
        return TTL_SECONDS;
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to sign JWT", e);
        }
    }

    private static String base64Url(String value) {
        return URL_ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64Url(byte[] value) {
        return URL_ENCODER.encodeToString(value);
    }

    private static String decode(String part) {
        return new String(URL_DECODER.decode(part), StandardCharsets.UTF_8);
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String jsonString(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyIndex = json.indexOf(pattern);
        if (keyIndex < 0) {
            return null;
        }
        int colon = json.indexOf(':', keyIndex + pattern.length());
        int firstQuote = json.indexOf('"', colon + 1);
        int secondQuote = json.indexOf('"', firstQuote + 1);
        if (colon < 0 || firstQuote < 0 || secondQuote < 0) {
            return null;
        }
        return json.substring(firstQuote + 1, secondQuote);
    }

    private static Long jsonLong(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyIndex = json.indexOf(pattern);
        if (keyIndex < 0) {
            return null;
        }
        int colon = json.indexOf(':', keyIndex + pattern.length());
        if (colon < 0) {
            return null;
        }
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        if (end == start) {
            return null;
        }
        return Long.parseLong(json.substring(start, end));
    }

    record Claims(String username, String displayName, String jti, long expiresAt) {
    }
}
