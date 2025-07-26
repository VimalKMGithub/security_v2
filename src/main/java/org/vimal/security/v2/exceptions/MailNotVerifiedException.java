package org.vimal.security.v2.exceptions;

import org.springframework.security.core.AuthenticationException;

public class MailNotVerifiedException extends AuthenticationException {
    public MailNotVerifiedException(String message) {
        super(message);
    }
}
