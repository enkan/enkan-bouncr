package enkan.security.bouncr;

import enkan.MiddlewareChain;
import enkan.annotation.Middleware;
import enkan.data.HttpRequest;
import enkan.data.HttpResponse;
import enkan.data.Routable;
import enkan.middleware.WebMiddleware;
import enkan.security.UserPrincipal;

import jakarta.annotation.security.RolesAllowed;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.stream.Stream;

import static enkan.util.BeanBuilder.*;

/**
 * Middleware for annotation-based authorization using {@link jakarta.annotation.security.RolesAllowed}.
 *
 * @author kawasima
 */
@Middleware(name = "authorizeControllerMethod", dependencies = "routing")
public class AuthorizeControllerMethodMiddleware implements WebMiddleware {
    /**
     * {@inheritDoc}
     */
    @Override
    public <NNREQ, NNRES> HttpResponse handle(HttpRequest request, MiddlewareChain<HttpRequest, HttpResponse, NNREQ, NNRES> chain) {
        Method m = ((Routable) request).getControllerMethod();
        Optional<UserPrincipal> principal = Stream.of(request.getPrincipal())
                .filter(UserPrincipal.class::isInstance)
                .map(UserPrincipal.class::cast)
                .findAny();

        RolesAllowed rolesAllowed = m.getAnnotation(RolesAllowed.class);
        if (rolesAllowed != null) {
            if (!principal.isPresent() || !Stream.of(rolesAllowed.value())
                    .anyMatch(permission -> principal.filter(p -> p.hasPermission(permission)).isPresent())) {
                return builder(HttpResponse.of("Not allowed"))
                        .set(HttpResponse::setStatus, 403)
                        .build();
            }
        }
        return castToHttpResponse(chain.next(request));
    }
}
