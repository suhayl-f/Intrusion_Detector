import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.stream.Collectors;

public class ThreatDetector {
    private static final String RESET = "\u001B[0m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RED = "\u001B[31m";
    private static final String BOLD_RED = "\u001B[1;31m";

    private final Map<String, List<LocalDateTime>> failedAttempts = new HashMap<>();
    private final List<SecurityAlert> incidentHistory = new ArrayList<>();

    private static final int THRESHOLD = 5;
    private static final int WINDOW_SECONDS = 60;
    private static final int BUSINESS_START_HOUR = 6;  // 06:00
    private static final int BUSINESS_END_HOUR = 22;   // 22:00

    public void analyze(LogEntry entry) {
        if ("Failed".equals(entry.status())) {
            failedAttempts.putIfAbsent(entry.sourceIP(), new ArrayList<>());
            List<LocalDateTime> timeStamps = failedAttempts.get(entry.sourceIP());
            timeStamps.add(entry.timeStamp());

            timeStamps.removeIf(time -> Duration.between(time, entry.timeStamp()).getSeconds() > WINDOW_SECONDS);

            // Use == THRESHOLD to prevent spamming duplicate alerts during a continuous attack
            if (timeStamps.size() == THRESHOLD) {
                triggerAlert("HIGH", "Brute-force SSH attempt detected", entry);
            }

            if ("root".equals(entry.user())) {
                triggerAlert("MEDIUM", "Failed root SSH login attempt", entry);
            }

        } else if ("Accepted".equals(entry.status())) {
            // Rule 1: Direct root login
            if ("root".equals(entry.user())) {
                triggerAlert("CRITICAL", "Successful root login", entry);
            }

            // Rule 2: Off-hours login anomaly
            int hour = entry.timeStamp().getHour();
            if (hour < BUSINESS_START_HOUR || hour >= BUSINESS_END_HOUR) {
                triggerAlert("MEDIUM", "Off-hours successful SSH login", entry);
            }

            // Rule 3: Login after recent failed attempts
            if (failedAttempts.containsKey(entry.sourceIP())) {
                List<LocalDateTime> timeStamps = failedAttempts.get(entry.sourceIP());
                timeStamps.removeIf(time -> Duration.between(time, entry.timeStamp()).getSeconds() > WINDOW_SECONDS);

                if (!timeStamps.isEmpty()) {
                    triggerAlert("CRITICAL", "Successful login AFTER failed attempts (Possible Compromise!)", entry);
                }
            }
            failedAttempts.remove(entry.sourceIP());
        }
    }

    private void triggerAlert(String severity, String message, LogEntry entry) {
        String color = switch (severity) {
            case "CRITICAL" -> BOLD_RED;
            case "HIGH" -> RED;
            case "MEDIUM" -> YELLOW;
            default -> RESET;
        };

        System.out.printf("%s[%s]%s %s | IP: %s | Target User: %s | Time: %s%n",
                color, severity, RESET, message, entry.sourceIP(), entry.user(), entry.timeStamp());

        incidentHistory.add(new SecurityAlert(severity, message, entry.sourceIP(), entry.user(), entry.timeStamp()));
        exportAlertsToJson("alerts.json");
    }

    public void exportAlertsToJson(String fileName) {
        String jsonBody = incidentHistory.stream()
                .map(SecurityAlert::toJson)
                .collect(Collectors.joining(",\n", "[\n", "\n]"));
        try {
            Files.writeString(Path.of(fileName), jsonBody);
        } catch (IOException e) {
            System.err.println("Failed to write JSON report: " + e.getMessage());
        }
    }
}
