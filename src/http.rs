use crate::auth::{AuthDb, RequestError, ensure_host_authorized, parse_and_authenticate};
use crate::config::{Config, Host, canonical_name};
use crate::dns::Rfc2136Writer;
use crate::rate::RateLimiter;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::header::{
    AUTHORIZATION, CONTENT_LENGTH, HeaderValue, TRANSFER_ENCODING, WWW_AUTHENTICATE,
};
use hyper::{Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct App {
    hosts: HashMap<String, Host>,
    auth: AuthDb,
    dns: Rfc2136Writer,
    rate: RateLimiter,
    timeout: Duration,
}

impl App {
    pub fn new(
        config: &Config,
        auth: AuthDb,
        dns: Rfc2136Writer,
    ) -> Result<Self, crate::config::ConfigError> {
        let hosts = config
            .hosts
            .iter()
            .map(|host| canonical_name(&host.hostname).map(|name| (name, host.clone())))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            hosts,
            auth,
            dns,
            rate: RateLimiter::new(
                config.global_requests_per_minute,
                config.per_host_updates_per_minute,
                config.unauthenticated_requests_per_peer_per_minute,
            ),
            timeout: Duration::from_secs(config.request_timeout_seconds),
        })
    }

    pub async fn handle(
        self: Arc<Self>,
        peer: IpAddr,
        request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let response = self.process(peer, request).await;
        Ok(response)
    }

    async fn process(&self, peer: IpAddr, request: Request<Incoming>) -> Response<Full<Bytes>> {
        if self.rate.peer_blocked(peer).await {
            return reply(StatusCode::TOO_MANY_REQUESTS, "911\n");
        }
        if request.method() != Method::GET {
            return self
                .unauthenticated(peer, StatusCode::METHOD_NOT_ALLOWED, "badagent\n")
                .await;
        }
        if request.headers().contains_key(CONTENT_LENGTH)
            || request.headers().contains_key(TRANSFER_ENCODING)
            || !request.body().is_end_stream()
        {
            return self
                .unauthenticated(peer, StatusCode::BAD_REQUEST, "badagent\n")
                .await;
        }
        let Ok(authorization) = request
            .headers()
            .get(AUTHORIZATION)
            .map(HeaderValue::to_str)
            .transpose()
        else {
            self.rate.record_unauthenticated(peer).await;
            return unauthorized();
        };
        let update = match parse_and_authenticate(request.uri(), authorization, &self.auth) {
            Ok(update) => update,
            Err(RequestError::Authentication) => {
                self.rate.record_unauthenticated(peer).await;
                return unauthorized();
            }
            Err(RequestError::Invalid) => {
                return self
                    .unauthenticated(peer, StatusCode::BAD_REQUEST, "notfqdn\n")
                    .await;
            }
        };
        let Ok(host) = ensure_host_authorized(&update, &self.hosts) else {
            self.rate.record_unauthenticated(peer).await;
            return reply(StatusCode::OK, "nohost\n");
        };
        if !self.rate.allow_authenticated(&update.hostname).await {
            return reply(StatusCode::TOO_MANY_REQUESTS, "911\n");
        }
        match tokio::time::timeout(self.timeout, self.dns.update(&host, update.address)).await {
            Ok(Ok(())) => reply(StatusCode::OK, &format!("good {}\n", update.address)),
            Ok(Err(error)) => {
                tracing::error!(error = %error, hostname = %update.hostname, "DNS update failed");
                reply(StatusCode::BAD_GATEWAY, "dnserr\n")
            }
            Err(_) => {
                tracing::error!(hostname = %update.hostname, "DNS update timed out");
                reply(StatusCode::GATEWAY_TIMEOUT, "911\n")
            }
        }
    }

    async fn unauthenticated(
        &self,
        peer: IpAddr,
        status: StatusCode,
        text: &str,
    ) -> Response<Full<Bytes>> {
        self.rate.record_unauthenticated(peer).await;
        reply(status, text)
    }
}

fn unauthorized() -> Response<Full<Bytes>> {
    let mut response = reply(StatusCode::UNAUTHORIZED, "badauth\n");
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"DynDNS update\", charset=\"UTF-8\""),
    );
    response
}

fn reply(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(text.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}
