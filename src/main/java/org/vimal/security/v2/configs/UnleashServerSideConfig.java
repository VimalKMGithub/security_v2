package org.vimal.security.v2.configs;

import io.getunleash.DefaultUnleash;
import io.getunleash.Unleash;
import io.getunleash.util.UnleashConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class UnleashServerSideConfig {
    private static final String UNLEASH_APP_NAME = "Security_V2";
    private static final String UNLEASH_INSTANCE_ID = "Security_V2_Instance_1";
    private final PropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return new DefaultUnleash(UnleashConfig.builder().appName(UNLEASH_APP_NAME).instanceId(UNLEASH_INSTANCE_ID)
                .unleashAPI(propertiesConfig.getUnleashUrl()).synchronousFetchOnInitialisation(true)
                .apiKey(propertiesConfig.getUnleashApiToken()).fetchTogglesInterval(5)
                .build());
    }
}
