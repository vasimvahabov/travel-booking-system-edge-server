package com.travelbookingsystem.edgeserver;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import java.time.Duration;

@Slf4j
@Testcontainers
@FieldDefaults(level = AccessLevel.PRIVATE)
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
class EdgeServerApplicationTests {

    static final int REDIS_PORT = 6379;
    static final int KEYCLOAK_PORT = 8080;

    @Container
    static GenericContainer<?> redisContainer =
            new GenericContainer<>(DockerImageName.parse("redis:8.2.1"))
                    .withExposedPorts(REDIS_PORT);

    @Container
    static GenericContainer<?> keycloakContainer = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.3"))
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "password")
            .withEnv("KC_HTTP_PORT", String.valueOf(KEYCLOAK_PORT))
            .withExposedPorts(KEYCLOAK_PORT)
            .withFileSystemBind("src/test/resources/keycloak", "/opt/keycloak/data/import", BindMode.READ_ONLY)
            .withCommand("start-dev --import-realm")
            .waitingFor(Wait.forHttp("/realms/travel-booking-system").forPort(KEYCLOAK_PORT).withStartupTimeout(Duration.ofMinutes(2)));

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", () -> redisContainer.getHost());
        registry.add("spring.data.redis.port", () -> redisContainer.getMappedPort(REDIS_PORT));

        var issuerUri = "http://" + keycloakContainer.getHost() + ":" + keycloakContainer.getMappedPort(KEYCLOAK_PORT) + "/realms/travel-booking-system";
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri",
                () -> issuerUri);
    }

    @Test
    void contextLoads() {
    }

}
