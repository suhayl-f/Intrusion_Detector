import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IpEnricher {
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private static final Map<String, String> CACHE = new HashMap<>();

    public static String getIpContext(String ip) {
        if (isPrivateIp(ip)) {
            return "Internal/Private Network";
        }

        if (CACHE.containsKey(ip)) {
            return CACHE.get(ip);
        }

        try {
            // Query free ip-api endpoint requesting only country and ISP
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://ip-api.com/json/" + ip + "?fields=status,country,isp"))
                    .timeout(Duration.ofSeconds(3)).GET().build();

            HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200 && response.body().contains("\"success\"")) {
                String country = extractJsonField(response.body(), "country");
                String isp = extractJsonField(response.body(), "isp");
                String result = country + " (" + isp + ")";
                CACHE.put(ip, result);
                return result;
            }

        } catch (Exception e) {

        }
        return "Unknown External Host";
    }

    private static boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")
                || ip.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*");
    }

    private static String extractJsonField(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\":\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        return matcher.find() ? matcher.group(1) : "Unknown";
    }
}
