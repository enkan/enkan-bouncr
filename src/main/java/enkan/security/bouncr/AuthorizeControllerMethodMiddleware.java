package enkan.security.bouncr;

import enkan.MiddlewareChain;
import enkan.annotation.Middleware;
import enkan.data.HttpRequest;
import enkan.data.HttpResponse;
import enkan.data.Routable;
import enkan.middleware.AbstractWebMiddleware;
import enkan.security.UserPrincipal;

import javax.annotation.security.RolesAllowed;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.stream.Stream;

import static enkan.util.BeanBuilder.*;

/**
 * The logging for annotation-based authorization.
 *
 * @author kawasima
 */
@Middleware(name = "authorizeControllerMethod", dependencies = "routing")
public class AuthorizeControllerMethodMiddleware<NRES> extends AbstractWebMiddleware<HttpRequest, NRES> {
    /**
     * {@inheritDoc}
     */
    @Override
    public HttpResponse handle(HttpRequest request, MiddlewareChain<HttpRequest, NRES, ?, ?> chain) {
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
