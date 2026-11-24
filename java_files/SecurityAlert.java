import java.time.LocalDateTime;

public record SecurityAlert(String severity, String ruleName, String sourceIP, String targetUser,
        LocalDateTime timeStamp) {
    // Formats the alert as a clean JSON object without needing external libraries
    public String toJson() {
        return String.format(
                "  {\n" +
                        "    \"severity\": \"%s\",\n" +
                        "    \"rule\": \"%s\",\n" +
                        "    \"source_ip\": \"%s\",\n" +
                        "    \"target_user\": \"%s\",\n" +
                        "    \"timestamp\": \"%s\"\n" +
                        "  }",
                severity, ruleName, sourceIP, targetUser, timeStamp
            );
    }
}
