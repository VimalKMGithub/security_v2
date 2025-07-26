package org.vimal.security.v2.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
public class Testing {
    @PostMapping("/testing")
    public ResponseEntity<String> testing() {
        return ResponseEntity.ok("Test successful");
    }
}
