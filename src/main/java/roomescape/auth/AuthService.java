package roomescape.auth;

import org.springframework.stereotype.Service;
import roomescape.member.Member;
import roomescape.member.MemberDao;
import roomescape.member.MemberResponse;

@Service
public class AuthService {

    private MemberDao memberDao;
    private JwtTokenProvider jwtTokenProvider;

    public AuthService(JwtTokenProvider jwtTokenProvider, MemberDao memberDao) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.memberDao = memberDao;
    }

    public MemberResponse findMemberByToken(String token) {
        String payload = jwtTokenProvider.getPayload(token);
        Member member = memberDao.findByName(payload);
        return new MemberResponse(member.getId(), member.getName(), member.getEmail());
    }

    public TokenResponse createToken(TokenRequest tokenRequest) {
        Member member = memberDao.findByEmailAndPassword(tokenRequest.getEmail(), tokenRequest.getPassword());
        String accessToken = jwtTokenProvider.createToken(member.getName());
        return new TokenResponse(accessToken);
    }
}

