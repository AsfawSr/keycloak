package com.asfaw.keycloak.util;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class TokenUtils {

    private TokenUtils() {}

    public static Long toLong(Object number) {
        if (number == null) return null;
        if (number instanceof Number) return ((Number) number).longValue();
        try {
            return Long.parseLong(number.toString());
        } catch (NumberFormatException e) {
            log.warn("Could not convert '{}' to Long", number);
            return null;
        }
    }
}
