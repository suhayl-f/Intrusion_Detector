import java.time.*;
import java.util.*;

public class ThreatDetector {
    // Maps an IP address to a list of timestamps when it failed to log in
    private final Map<String, List<LocalDateTime>> failedAttempts = new HashMap<>();
    private static final int THRESHOLD = 5;
    private static final int WINDOW_SECONDS = 60;

    public void analyze(LogEntry entry) {
        if ("Failed".equals(entry.status())) {
            failedAttempts.putIfAbsent(entry.sourceIP(), new ArrayList<>());
            List<LocalDateTime> timeStamps = failedAttempts.get(entry.sourceIP());
            timeStamps.add(entry.timeStamp());

            // Remove timestamps older than 60 seconds from the current event
            timeStamps.removeIf(time -> Duration.between(time, entry.timeStamp()).getSeconds() > WINDOW_SECONDS);

            if (timeStamps.size() >= THRESHOLD) {
                triggerAlert("HIGH", "Brute-force SSH attempt detected", entry);
            }

        } else if ("Accepted".equals(entry.status())) {
            // Reset counter on successful login, or alert if this IP previously failed!
            if (failedAttempts.containsKey(entry.sourceIP()) && !failedAttempts.get(entry.sourceIP()).isEmpty()) {
                triggerAlert("CRITICAL", "Successful login AFTER failed attempts (Possible Compromise!)", entry);
            }
            failedAttempts.remove(entry.sourceIP());
        }
    }

    private void triggerAlert(String severity, String message, LogEntry entry) {
        System.out.printf("[%s] %s | IP: %s | Target User: %s | Time: %s%n", severity, message, entry.sourceIP(),
                entry.user(), entry.timeStamp());
    }
}
