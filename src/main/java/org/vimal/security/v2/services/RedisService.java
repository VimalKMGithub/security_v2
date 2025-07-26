package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collection;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class RedisService {
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    private final RedisTemplate<Object, Object> redisTemplate;

    public void save(Object key,
                     Object value,
                     Duration TTL) {
        redisTemplate.opsForValue().set(key, value, TTL);
    }

    public Object get(Object key) {
        return redisTemplate.opsForValue().get(key);
    }

    public Collection<Object> get(Collection<Object> keys) {
        return redisTemplate.opsForValue().multiGet(keys);
    }

    public void delete(Object key) {
        redisTemplate.delete(key);
    }

    public void delete(Collection<Object> keys) {
        redisTemplate.delete(keys);
    }

    public void flushDb() {
        Objects.requireNonNull(redisTemplate.getConnectionFactory())
                .getConnection()
                .serverCommands()
                .flushDb();
    }
}
