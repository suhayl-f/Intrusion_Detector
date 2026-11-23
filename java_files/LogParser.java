import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser {
    private static final Pattern SSH_PATTERN = Pattern.compile("^(\\w{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}).*(Failed|Accepted) password for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)");

    public static Optional<LogEntry> parse(String line){

        Matcher matcher = SSH_PATTERN.matcher(line);

        if(matcher.find()){

            String raw_time = "2026" + matcher.group(1);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy MMM dd HH:mm:ss");
            LocalDateTime timeStamp = LocalDateTime.parse(raw_time,formatter);

            String status = matcher.group(2);
            String username = matcher.group(3);
            String ip = matcher.group(4);

            return Optional.of(new LogEntry(timeStamp, status, username, ip));
        }
        return Optional.empty();
    }

}
