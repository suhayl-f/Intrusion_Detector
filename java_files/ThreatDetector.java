import java.time.*;
import java.util.*;

public class ThreatDetector {
    // ANSI Color Codes for Terminal Output
    private static final String RESET = "\u001B[0m";
    private static final String YELLOW = "\u001B[33m";       // Medium / Warning
    private static final String RED = "\u001B[31m";          // High
    private static final String BOLD_RED = "\u001B[1;31m";   // Critical

    private final Map<String, List<LocalDateTime>> failedAttempts = new HashMap<>();
    private static final int THRESHOLD = 5;
    private static final int WINDOW_SECONDS = 60;

    public void analyze(LogEntry entry) {
        if ("Failed".equals(entry.status())) {
            failedAttempts.putIfAbsent(entry.sourceIP(), new ArrayList<>());
            List<LocalDateTime> timeStamps = failedAttempts.get(entry.sourceIP());
            timeStamps.add(entry.timeStamp());

            timeStamps.removeIf(time -> Duration.between(time, entry.timeStamp()).getSeconds() > WINDOW_SECONDS);

            if (timeStamps.size() >= THRESHOLD) {
                triggerAlert("HIGH", "Brute-force SSH attempt detected", entry);
            }

            if ("root".equals(entry.user())){
                triggerAlert("MEDIUM", "Root SSH attempt detected", entry);
            }

        } else if ("Accepted".equals(entry.status())) {
            if ("root".equals(entry.user())){
                    triggerAlert("CRITICAL", "Successful Root login", entry);
                }

            if (failedAttempts.containsKey(entry.sourceIP())) {
                List<LocalDateTime> timeStamps = failedAttempts.get(entry.sourceIP());
                // Prune expired failures so normal typos from minutes ago don't trigger false alarms
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
    }
}
