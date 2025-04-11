package roomescape.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${security.jwt.token.secret-key}")
    private String secretKeyPlain;

    @Value("${security.jwt.token.expire-length}")
    private long validityInMilliseconds;

    private SecretKey secretKey;

    @PostConstruct
    protected void init() {
        // 문자열을 byte 배열로 바꿔서 SecretKey 객체로 변환
        this.secretKey = Keys.hmacShaKeyFor(secretKeyPlain.getBytes());
    }

    public String createToken(String payload) {
        Claims claims = Jwts.claims().setSubject(payload);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256) // SecretKey 사용
                .compact();
    }

    public String getPayload(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey) // parserBuilder 사용
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
