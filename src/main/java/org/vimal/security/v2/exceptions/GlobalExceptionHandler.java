package org.vimal.security.v2.exceptions;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.vimal.security.v2.utils.JSONUtility;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, String>> handleAuthenticationException(AuthenticationException ex) {
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized", "message", ex.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(403).body(Map.of("error", "Forbidden", "message", ex.getMessage()));
    }

    @ExceptionHandler({BadRequestException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, String>> handleBadRequestExceptions(Exception ex) {
        return ResponseEntity.badRequest().body(Map.of("error", "Bad Request", "message", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) throws JsonProcessingException {
        var errorResponse = new LinkedHashMap<String, Object>();
        errorResponse.put("severity", "Error");
        errorResponse.put("message", ex.getMessage());
        var innerErrorData = new LinkedHashMap<>();
        innerErrorData.put("exception", ex.toString());
        innerErrorData.put("stack", formatStackTrace(ex));
        errorResponse.put("innerErrorData", innerErrorData);
        log.error("An unexpected error occurred: {}\n{}", ex.getMessage(), JSONUtility.toJson(errorResponse));
        return ResponseEntity.internalServerError().body(errorResponse);
    }

    public List<String> formatStackTrace(Throwable ex) {
        return Arrays.stream(ex.getStackTrace()).map(ste -> ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() + ":" + ste.getLineNumber() + ")").toList();
    }
}
