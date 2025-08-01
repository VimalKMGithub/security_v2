package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDetailsResultDto {
    private boolean isModified;
    private boolean shouldRemoveTokens;
    private Collection<String> invalidInputs;
}
