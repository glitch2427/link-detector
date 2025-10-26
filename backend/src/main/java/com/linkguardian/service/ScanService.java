package com.linkguardian.service;

import com.linkguardian.dto.ScanRequest;
import com.linkguardian.dto.ScanResponse;
import com.linkguardian.model.ScannedLink;
import com.linkguardian.model.User;
import com.linkguardian.repository.ScannedLinkRepository;
import com.linkguardian.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;

@Service
public class ScanService {

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${google.safebrowsing.api.key}")
    private String googleApiKey;

    private final ScannedLinkRepository scannedLinkRepository;
    private final UserRepository userRepository;
    private final HttpClient httpClient;

    public ScanService(ScannedLinkRepository scannedLinkRepository, UserRepository userRepository) {
        this.scannedLinkRepository = scannedLinkRepository;
        this.userRepository = userRepository;
        this.httpClient = HttpClient.newHttpClient();
    }

    public ScanResponse scanUrl(ScanRequest request, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String url = request.getUrl();
        String vtResult = checkVirusTotal(url);
        String gsbResult = checkGoogleSafeBrowsing(url);
        String heuristicResult = checkHeuristics(url);
        boolean safe = determineOverallSafety(vtResult, gsbResult, heuristicResult);

        ScannedLink scannedLink = new ScannedLink(user.getId(), url, safe);
        scannedLink.setVirusTotalResult(vtResult);
        scannedLink.setGoogleSafeBrowsingResult(gsbResult);
        scannedLink.setHeuristicResult(heuristicResult);
        scannedLinkRepository.save(scannedLink);

        String message = safe ? "No threats detected" : "Potential threats detected";
        return new ScanResponse(url, safe, vtResult, gsbResult, heuristicResult, message);
    }

    private String checkVirusTotal(String url) {
        try {
            String urlId = java.util.Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(url.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            String lookupUrl = "https://www.virustotal.com/api/v3/urls/" + urlId;
            HttpRequest lookupRequest = HttpRequest.newBuilder()
                    .uri(URI.create(lookupUrl))
                    .header("x-apikey", virusTotalApiKey)
                    .GET()
                    .build();

            HttpResponse<String> lookupResponse = httpClient.send(lookupRequest, HttpResponse.BodyHandlers.ofString());

            if (lookupResponse.statusCode() == 200) {
                String body = lookupResponse.body();
                int malicious = extractStatValue(body, "\"malicious\":");
                int suspicious = extractStatValue(body, "\"suspicious\":");
                int harmless = extractStatValue(body, "\"harmless\":");
                
                if (malicious == -1 && suspicious == -1 && harmless == -1) {
                    submitUrlToVirusTotal(url);
                    return "✅ URL submitted to VirusTotal for analysis";
                }
                
                if (malicious == 0 && suspicious == 0) {
                    return String.format("✅ Clean - VirusTotal (0 threats, %d safe)", harmless);
                } else {
                    return String.format("⚠️ Threats - %d malicious, %d suspicious", malicious, suspicious);
                }
            } else if (lookupResponse.statusCode() == 404) {
                submitUrlToVirusTotal(url);
                return "✅ URL submitted to VirusTotal for analysis";
            } else {
                return "❓ VirusTotal unavailable (Status: " + lookupResponse.statusCode() + ")";
            }
        } catch (Exception e) {
            return "❌ VirusTotal error: " + e.getMessage();
        }
    }

    private void submitUrlToVirusTotal(String url) {
        try {
            String submitUrl = "https://www.virustotal.com/api/v3/urls";
            HttpRequest submitRequest = HttpRequest.newBuilder()
                    .uri(URI.create(submitUrl))
                    .header("x-apikey", virusTotalApiKey)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("url=" + url))
                    .build();
            httpClient.send(submitRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ignored) {}
    }

    private int extractStatValue(String json, String pattern) {
        int index = json.indexOf(pattern);
        if (index == -1) return -1;
        index += pattern.length();
        StringBuilder num = new StringBuilder();
        while (index < json.length() && (Character.isDigit(json.charAt(index)) || json.charAt(index) == '-')) {
            num.append(json.charAt(index));
            index++;
        }
        if (num.length() == 0) return -1;
        try {
            return Integer.parseInt(num.toString());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private String checkGoogleSafeBrowsing(String url) {
        try {
            String apiUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + googleApiKey;
            String requestBody = String.format("""
                {
                    "client": {"clientId": "linkguardian", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": "%s"}]
                    }
                }
                """, url);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return response.body().contains("matches") ? "⚠️ Flagged by Google Safe Browsing" : "✅ Clean - No threats found";
            } else {
                return "❓ Google Safe Browsing unavailable";
            }
        } catch (Exception e) {
            return "❌ Google Safe Browsing error";
        }
    }

    private String checkHeuristics(String url) {
        int score = 0;
        StringBuilder analysis = new StringBuilder();
        String lowerUrl = url.toLowerCase();

        if (lowerUrl.startsWith("https://")) {
            score += 2;
            analysis.append("✅ HTTPS (+2). ");
        } else if (lowerUrl.startsWith("http://")) {
            score -= 2;
            analysis.append("⚠️ No HTTPS (-2). ");
        }

        if (Pattern.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*", lowerUrl)) {
            score -= 5;
            analysis.append("⚠️ IP address (-5). ");
        }

        String[] shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"};
        for (String s : shorteners) {
            if (lowerUrl.contains(s)) {
                score -= 3;
                analysis.append("⚠️ URL shortener (-3). ");
                break;
            }
        }

        String[] keywords = {"verify", "account", "suspend", "confirm", "update", "secure", "bank", "paypal",
            "login", "signin", "password", "urgent", "winner", "free", "prize", "crypto", "bitcoin"};
        int keywordCount = 0;
        for (String k : keywords) {
            if (lowerUrl.contains(k)) keywordCount++;
        }
        if (keywordCount > 0) {
            score -= (keywordCount * 2);
            analysis.append(String.format("⚠️ %d suspicious keywords (-%d). ", keywordCount, keywordCount * 2));
        }

        if (url.length() > 100) {
            score -= 1;
            analysis.append("⚠️ Long URL (-1). ");
        }

        return score >= 0 ? "✅ SAFE (Score: " + score + ") - " + analysis : "⚠️ SUSPICIOUS (Score: " + score + ") - " + analysis;
    }

    private boolean determineOverallSafety(String vtResult, String gsbResult, String heuristicResult) {
        return !(vtResult.contains("⚠️") || vtResult.contains("❌") ||
                gsbResult.contains("⚠️") || gsbResult.contains("❌") ||
                heuristicResult.contains("⚠️"));
    }
}

