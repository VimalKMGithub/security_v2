package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {
    private final RetryMailService retryMailService;

    public void sendEmail(String to,
                          String subject,
                          String text) {
        retryMailService.sendEmail(to, subject, text);
    }

    public void sendOtp(String to,
                        String subject,
                        String otp) {
        var text = String.format("""
                        Your verification otp is: %s
                        This otp will expire in 5 minutes.
                        """,
                otp
        );
        sendEmail(to, subject, text);
    }

    @Async
    public void sendOtpAsync(String to,
                             String subject,
                             String otp) {
        sendOtp(to, subject, otp);
    }

    public void sendLinkEmail(String to,
                              String subject,
                              String link) {
        var text = String.format("""
                        Your verification link is: %s
                        This link will expire in 5 minutes.
                        """,
                link
        );
        sendEmail(to, subject, text);
    }

    @Async
    public void sendLinkEmailAsync(String to,
                                   String subject,
                                   String link) {
        sendLinkEmail(to, subject, link);
    }

    public void sendAccountDeletionConfirmation(String to,
                                                String subject) {
        var text = """
                Your account has been deleted successfully & will be completely removed from backup after 30 days.
                If this was a mistake or you want to recover your account or not done by you, please contact support immediately.
                """;
        sendEmail(to, subject, text);
    }

    @Async
    public void sendAccountDeletionConfirmationAsync(String to,
                                                     String subject) {
        sendAccountDeletionConfirmation(to, subject);
    }
}
