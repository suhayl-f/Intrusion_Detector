import java.time.LocalDateTime;

public record LogEntry(LocalDateTime timeStamp, String status, String user, String sourceIP) {

}
