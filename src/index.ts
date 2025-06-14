interface Env {
    CUSTOM_DOMAIN: string;
    MODE?: string;
    TARGET_UPSTREAM?: string;
}

interface WwwAuthenticate {
    realm: string;
    service: string;
}

interface RouteMap {
    [key: string]: string;
}

const dockerHub = "https://registry-1.docker.io";

function getRoutes(customDomain: string): RouteMap {
    return {
        // Production
        [`docker.${customDomain}`]: dockerHub,
        [`quay.${customDomain}`]: "https://quay.io",
        [`gcr.${customDomain}`]: "https://gcr.io",
        [`k8s-gcr.${customDomain}`]: "https://k8s.gcr.io",
        [`k8s.${customDomain}`]: "https://registry.k8s.io",
        [`ghcr.${customDomain}`]: "https://ghcr.io",
        [`cloudsmith.${customDomain}`]: "https://docker.cloudsmith.io",
        [`ecr.${customDomain}`]: "https://public.ecr.aws",

        // Staging
        [`docker-staging.${customDomain}`]: dockerHub
    };
}

function routeByHosts(host: string, routes: RouteMap, mode?: string, targetUpstream?: string): string {
    if (host in routes) {
        return routes[host];
    }
    if (mode === "debug" && targetUpstream) {
        return targetUpstream;
    }
    return "";
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
    const routes = getRoutes(env.CUSTOM_DOMAIN);
    const url = new URL(request.url);

    if (url.pathname === "/") {
        return Response.redirect(url.protocol + "//" + url.host + "/v2/", 301);
    }

    const upstream = routeByHosts(url.hostname, routes, env.MODE, env.TARGET_UPSTREAM);
    if (upstream === "") {
        return new Response(
            JSON.stringify({
                routes: routes
            }),
            {
                status: 404,
                headers: {
                    "Content-Type": "application/json"
                }
            }
        );
    }

    const isDockerHub = upstream === dockerHub;
    const authorization = request.headers.get("Authorization");

    if (url.pathname === "/v2/") {
        const newUrl = new URL(upstream + "/v2/");
        const headers = new Headers();
        if (authorization) {
            headers.set("Authorization", authorization);
        }
        // check if need to authenticate
        const resp = await fetch(newUrl.toString(), {
            method: "GET",
            headers: headers,
            redirect: "follow"
        });
        if (resp.status === 401) {
            return responseUnauthorized(url, env.MODE);
        }
        return resp;
    }

    // get token
    if (url.pathname === "/v2/auth") {
        const newUrl = new URL(upstream + "/v2/");
        const resp = await fetch(newUrl.toString(), {
            method: "GET",
            redirect: "follow"
        });
        if (resp.status !== 401) {
            return resp;
        }
        const authenticateStr = resp.headers.get("WWW-Authenticate");
        if (authenticateStr === null) {
            return resp;
        }
        const wwwAuthenticate = parseAuthenticate(authenticateStr);
        let scope = url.searchParams.get("scope");
        // autocomplete repo part into scope for DockerHub library images
        // Example: repository:busybox:pull => repository:library/busybox:pull
        if (scope && isDockerHub) {
            const scopeParts = scope.split(":");
            if (scopeParts.length === 3 && !scopeParts[1].includes("/")) {
                scopeParts[1] = "library/" + scopeParts[1];
                scope = scopeParts.join(":");
            }
        }
        return await fetchToken(wwwAuthenticate, scope, authorization);
    }

    // redirect for DockerHub library images
    // Example: /v2/busybox/manifests/latest => /v2/library/busybox/manifests/latest
    if (isDockerHub) {
        const pathParts = url.pathname.split("/");
        if (pathParts.length === 5) {
            pathParts.splice(2, 0, "library");
            const redirectUrl = new URL(url);
            redirectUrl.pathname = pathParts.join("/");
            return Response.redirect(redirectUrl.toString(), 301);
        }
    }

    // forward requests
    const newUrl = new URL(upstream + url.pathname);
    const newReq = new Request(newUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        // don't follow redirect to dockerhub blob upstream
        redirect: isDockerHub ? "manual" : "follow"
    });
    const resp = await fetch(newReq);
    if (resp.status === 401) {
        return responseUnauthorized(url, env.MODE);
    }
    // handle dockerhub blob redirect manually
    if (isDockerHub && resp.status === 307) {
        const location = resp.headers.get("Location");
        if (location) {
            const redirectResp = await fetch(location, {
                method: "GET",
                redirect: "follow"
            });
            return redirectResp;
        }
    }
    return resp;
}

function parseAuthenticate(authenticateStr: string): WwwAuthenticate {
    // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
    // match strings after =" and before "
    const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
    const matches = authenticateStr.match(re);
    if (matches === null || matches.length < 2) {
        throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
    }
    return {
        realm: matches[0],
        service: matches[1]
    };
}

async function fetchToken(wwwAuthenticate: WwwAuthenticate, scope: string | null, authorization: string | null): Promise<Response> {
    const url = new URL(wwwAuthenticate.realm);
    if (wwwAuthenticate.service.length) {
        url.searchParams.set("service", wwwAuthenticate.service);
    }
    if (scope) {
        url.searchParams.set("scope", scope);
    }
    const headers = new Headers();
    if (authorization) {
        headers.set("Authorization", authorization);
    }
    return await fetch(url.toString(), { method: "GET", headers: headers });
}

function responseUnauthorized(url: URL, mode?: string): Response {
    const headers = new Headers();
    if (mode === "debug") {
        headers.set(
            "Www-Authenticate",
            `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`
        );
    } else {
        headers.set(
            "Www-Authenticate",
            `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
        );
    }
    return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
        status: 401,
        headers: headers
    });
}

export default {
    fetch: handleRequest,
} satisfies ExportedHandler<Env>;
