package mate.academy.security.jwt;

import java.lang.reflect.Field;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import mate.academy.model.Role;
import mate.academy.model.User;
import mate.academy.security.CustomUserDetailsService;
import mate.academy.service.UserService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

class JwtTokenProviderTest {

    private UserService userService;
    private UserDetailsService userDetailsService;
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        userService = Mockito.mock(UserService.class);
        userDetailsService = new CustomUserDetailsService(userService);
        jwtTokenProvider = new JwtTokenProvider(userDetailsService);
        Class<? extends JwtTokenProvider> clazzJwtTokenProvider = jwtTokenProvider.getClass();
        try {
            Field secretKey = clazzJwtTokenProvider.getDeclaredField("secretKey");
            secretKey.setAccessible(true);
            String valueSecret = Base64.getEncoder().encodeToString("secret".getBytes());
            secretKey.set(jwtTokenProvider, valueSecret);

            Field valueTime = clazzJwtTokenProvider.getDeclaredField("validityInMilliseconds");
            valueTime.setAccessible(true);
            valueTime.set(jwtTokenProvider, 3600000);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException("Field not found", e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Can't set value to field", e);
        }
    }

    @Test
    void createToken_ok() {
        String login = "admin@server.com";
        List<String> roles = new LinkedList<>();
        roles.add(Role.RoleName.USER.name());

        String actualToken = jwtTokenProvider.createToken(login, roles);
        Assertions.assertNotNull(actualToken, "Token can't be empty");
    }

    @Test
    void getAuthentication_ok() {
        String userEmail = "admin@server.com";
        String password = "12345678";
        Role role = new Role();
        role.setRoleName(Role.RoleName.USER);
        List<String> roles = new LinkedList<>();
        roles.add(role.getRoleName().name());
        String token = jwtTokenProvider.createToken(userEmail, roles);

        User user = new User();
        user.setEmail(userEmail);
        user.setPassword(password);
        user.setRoles(Set.of(role));

        Mockito.when(userService.findByEmail(userEmail)).thenReturn(Optional.of(user));

        Authentication actual = jwtTokenProvider.getAuthentication(token);
        Assertions.assertNotNull(actual);
    }

    @Test
    void getUsername_ok() {
        String expected = "admin@server.com";
        List<String> roles = new LinkedList<>();
        roles.add(Role.RoleName.USER.name());
        String token = jwtTokenProvider.createToken(expected, roles);

        String actual = jwtTokenProvider.getUsername(token);
        Assertions.assertEquals(expected, actual);
    }

    // todo:
    //    @Test
    //    void resolveToken_ok() {
    //    }

    @Test
    void validateToken_ok() {
        String expected = "admin@server.com";
        List<String> roles = new LinkedList<>();
        roles.add(Role.RoleName.USER.name());
        String token = jwtTokenProvider.createToken(expected, roles);

        boolean actual = jwtTokenProvider.validateToken(token);
        Assertions.assertTrue(actual);
    }

    @Test
    void validateToken_error() {
        String tokenNotValid = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbkBzZXJ2ZXIuY29tIiwicm9sZXMiOlsiVVNFUiJdLCJpYXQiOjE2Nzc2ODAzMzUsImV4cCI6MTY3NzY4MzkzNX0.vH6HDUAUFnXXZBUyKq1GteG40Pgn1X29qqUKQtSLybw";
        try {
            jwtTokenProvider.validateToken(tokenNotValid);
        } catch (Exception e) {
            Assertions.assertEquals("Expired or invalid JWT token", e.getMessage());
            return;
        }
        Assertions.fail();
    }
}