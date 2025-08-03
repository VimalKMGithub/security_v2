package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {
    private final RetryMailService retryMailService;

    public enum MailType {
        OTP,
        LINK,
        ACCOUNT_DELETION_CONFIRMATION,
        PASSWORD_RESET_CONFIRMATION,
        SELF_PASSWORD_CHANGE_CONFIRMATION,
        SELF_EMAIL_CHANGE_CONFIRMATION,
        SELF_UPDATE_DETAILS_CONFIRMATION,
        SELF_MFA_ENABLE_DISABLE_CONFIRMATION
    }

    private static final String OTP_TEMPLATE = """
            Your verification otp is: %s
            This otp will expire in 5 minutes.
            """;
    private static final String LINK_TEMPLATE = """
            Your verification link is: %s
            This link will expire in 5 minutes.
            """;
    private static final String ACCOUNT_DELETION_CONFIRMATION_TEMPLATE = """
            Your account has been deleted successfully & will be completely removed from backup after 30 days.
            If this was a mistake or you want to recover your account or not done by you or if you want to remove your account from backup immediately, please contact support.
            """;
    private static final String PASSWORD_RESET_CONFIRMATION_TEMPLATE = """
            Your password has been reset successfully.
            If this was not done by you, please contact support immediately.
            """;
    private static final String SELF_PASSWORD_CHANGE_CONFIRMATION_TEMPLATE = """
            Your password has been changed successfully.
            If this was not done by you, please contact support immediately.
            """;
    private static final String SELF_EMAIL_CHANGE_CONFIRMATION_TEMPLATE = """
            Your email has been changed successfully.
            If this was not done by you, please contact support immediately.
            """;
    private static final String SELF_UPDATE_DETAILS_CONFIRMATION_TEMPLATE = """
            Your details have been updated successfully.
            If this was not done by you, please contact support immediately.
            """;
    private static final String SELF_MFA_ENABLE_DISABLE_CONFIRMATION_TEMPLATE = """
            %s.
            If this was not done by you, please contact support immediately.
            """;

    private void sendEmail(String to,
                           String subject,
                           String text) {
        retryMailService.sendEmail(to, subject, text);
    }

    private void sendEmail(String to,
                           String subject,
                           String value,
                           MailType mailType) {
        var text = switch (mailType) {
            case OTP -> String.format(OTP_TEMPLATE, value);
            case LINK -> String.format(LINK_TEMPLATE, value);
            case ACCOUNT_DELETION_CONFIRMATION -> ACCOUNT_DELETION_CONFIRMATION_TEMPLATE;
            case PASSWORD_RESET_CONFIRMATION -> PASSWORD_RESET_CONFIRMATION_TEMPLATE;
            case SELF_PASSWORD_CHANGE_CONFIRMATION -> SELF_PASSWORD_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_EMAIL_CHANGE_CONFIRMATION -> SELF_EMAIL_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_UPDATE_DETAILS_CONFIRMATION -> SELF_UPDATE_DETAILS_CONFIRMATION_TEMPLATE;
            case SELF_MFA_ENABLE_DISABLE_CONFIRMATION ->
                    String.format(SELF_MFA_ENABLE_DISABLE_CONFIRMATION_TEMPLATE, value);
        };
        sendEmail(to, subject, text);
    }

    @Async
    public void sendEmailAsync(String to,
                               String subject,
                               String value,
                               MailType mailType) {
        sendEmail(to, subject, value, mailType);
    }
}
