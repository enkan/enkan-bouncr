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
        RolesAllowed rolesAllowed = m.getAnnotation(RolesAllowed.class);
        if (rolesAllowed != null) {
            if (!(request.getPrincipal() instanceof UserPrincipal principal)
                    || Stream.of(rolesAllowed.value()).noneMatch(principal::hasPermission)) {
                return builder(HttpResponse.of("Not allowed"))
                        .set(HttpResponse::setStatus, 403)
                        .build();
            }
        }
        return castToHttpResponse(chain.next(request));
    }
}
