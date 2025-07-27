package org.vimal.security.v2.utils;

import java.util.Collection;
import java.util.Set;

public class EmailSanitizerUtility {
    public static final Collection<String> REMOVE_DOTS = Set.of("gmail.com", "googlemail.com");
    public static final Collection<String> REMOVE_ALIAS_PART = Set.of("gmail.com", "googlemail.com", "live.com", "protonmail.com", "hotmail.com", "outlook.com");

    public static String sanitizeEmail(String email) {
        var lowerCasedEmail = email.trim().toLowerCase();
        var atIndex = lowerCasedEmail.indexOf('@');
        var local = lowerCasedEmail.substring(0, atIndex);
        var domain = lowerCasedEmail.substring(atIndex + 1);
        if (REMOVE_DOTS.contains(domain)) local = local.replace(".", "");
        if (REMOVE_ALIAS_PART.contains(domain)) {
            var plusIndex = local.indexOf('+');
            if (plusIndex != -1) local = local.substring(0, plusIndex);
        }
        return local + "@" + domain;
    }
}
