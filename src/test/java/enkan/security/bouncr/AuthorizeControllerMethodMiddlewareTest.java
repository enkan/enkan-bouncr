package enkan.security.bouncr;

import enkan.Endpoint;
import enkan.chain.DefaultMiddlewareChain;
import enkan.collection.Headers;
import enkan.data.DefaultHttpRequest;
import enkan.data.HttpResponse;
import enkan.data.Routable;
import enkan.util.Predicates;
import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthorizeControllerMethodMiddlewareTest {

    private AuthorizeControllerMethodMiddleware middleware;

    @BeforeEach
    public void setup() {
        middleware = new AuthorizeControllerMethodMiddleware();
    }

    /** Routable + HttpRequest test double */
    private static class RoutableRequest extends DefaultHttpRequest implements Routable {
        private Principal principal;

        public RoutableRequest(Method controllerMethod, Principal principal) {
            setHeaders(Headers.empty());
            setControllerMethod(controllerMethod);
            this.principal = principal;
        }

        @Override
        public Principal getPrincipal() {
            return principal;
        }

        @Override
        public void setPrincipal(Principal principal) {
            this.principal = principal;
        }
    }

    /** Dummy controller class for method annotation testing */
    static class DummyController {
        @RolesAllowed("admin")
        public void adminOnly() {}

        @RolesAllowed({"read", "write"})
        public void multiRole() {}

        public void noAnnotation() {}
    }

    private static Method method(String name) throws NoSuchMethodException {
        return DummyController.class.getMethod(name);
    }

    private UserPermissionPrincipal principalWith(String... permissions) {
        return new UserPermissionPrincipal(1L, "user", java.util.Map.of(), Set.of(permissions));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private HttpResponse invoke(RoutableRequest req) {
        Endpoint<RoutableRequest, HttpResponse> okEndpoint = r -> HttpResponse.of("OK");
        DefaultMiddlewareChain<RoutableRequest, HttpResponse, RoutableRequest, HttpResponse> endpointChain =
                new DefaultMiddlewareChain<>(Predicates.any(), "endpoint", okEndpoint);
        // middleware is Middleware<HttpRequest, HttpResponse, NREQ, NRES>; wrap it to accept RoutableRequest
        enkan.Middleware<RoutableRequest, HttpResponse, RoutableRequest, HttpResponse> wrapper =
                new enkan.Middleware<RoutableRequest, HttpResponse, RoutableRequest, HttpResponse>() {
                    @Override
                    public <NNREQ, NNRES> HttpResponse handle(RoutableRequest r,
                            enkan.MiddlewareChain<RoutableRequest, HttpResponse, NNREQ, NNRES> chain) {
                        return middleware.handle(r, (enkan.MiddlewareChain) chain);
                    }
                };
        DefaultMiddlewareChain<RoutableRequest, HttpResponse, RoutableRequest, HttpResponse> chain =
                new DefaultMiddlewareChain<>(Predicates.any(), null, wrapper);
        chain.setNext(endpointChain);
        return chain.next(req);
    }

    @Test
    public void allowsWhenNoRolesAllowedAnnotation() throws Exception {
        RoutableRequest req = new RoutableRequest(method("noAnnotation"), principalWith("anything"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    public void allowsWhenNoPrincipalAndNoAnnotation() throws Exception {
        RoutableRequest req = new RoutableRequest(method("noAnnotation"), null);
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    public void forbidsWhenNoPrincipalAndRolesRequired() throws Exception {
        RoutableRequest req = new RoutableRequest(method("adminOnly"), null);
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(403);
    }

    @Test
    public void allowsWhenPrincipalHasRequiredRole() throws Exception {
        RoutableRequest req = new RoutableRequest(method("adminOnly"), principalWith("admin"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    public void forbidsWhenPrincipalLacksRequiredRole() throws Exception {
        RoutableRequest req = new RoutableRequest(method("adminOnly"), principalWith("read"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(403);
    }

    @Test
    public void allowsWhenPrincipalHasOneOfMultipleRoles() throws Exception {
        RoutableRequest req = new RoutableRequest(method("multiRole"), principalWith("read"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    public void forbidsWhenPrincipalHasNoneOfMultipleRoles() throws Exception {
        RoutableRequest req = new RoutableRequest(method("multiRole"), principalWith("admin"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(403);
    }

    @Test
    public void forbids403ResponseBodyIsNotAllowed() throws Exception {
        RoutableRequest req = new RoutableRequest(method("adminOnly"), principalWith("other"));
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(403);
    }

    @Test
    public void nonUserPrincipalIsIgnored() throws Exception {
        // A Principal that is NOT a UserPrincipal should be treated as unauthenticated
        Principal nonUserPrincipal = () -> "some-system-principal";
        RoutableRequest req = new RoutableRequest(method("adminOnly"), nonUserPrincipal);
        HttpResponse res = invoke(req);
        assertThat(res.getStatus()).isEqualTo(403);
    }
}
