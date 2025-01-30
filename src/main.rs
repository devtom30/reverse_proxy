use hyper::header::{ToStrError, SET_COOKIE};
use hyper::http::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::{convert::Infallible, net::SocketAddr};
use std::ops::{Add, DerefMut};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use valkey::Client;

const TOKEN_NAME: &str = "dop_token";

fn debug_request(req: Request<Body>) -> Result<Response<Body>, Infallible>  {
    let body_str = format!("{:?}", req);
    Ok(Response::new(Body::from(body_str)))
}

async fn handle(client_ip: IpAddr, req: Request<Body>, shared: Arc<Mutex<SharedState>>) -> Result<Response<Body>, Infallible> {
    let tag_extracted_option = extract_tag_from_request(req.uri().path());

    let mut redirect_uri = String::from("http://127.0.0.1:8084");
    if tag_extracted_option.is_none() {
        // no tag requested
        // let's see if we have a valid token
        // look into cookie for our token
        let cookie_hashmap = extract_cookie_map(&req);
        let mut tag_requested = String::from("");
        let token_in_cookie = cookie_hashmap.get(&String::from(TOKEN_NAME));
        if token_in_cookie.is_none() {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty()).unwrap());
        }

        // we have a token, let's see if it's valid
        let token = token_in_cookie.unwrap();
        match find_tag_relative_to_token(token, &shared.lock().as_ref().unwrap().map) {
            // invalid token
            None => {
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty()).unwrap())
            }
            // valid token relative to tag
            Some(tag) => {
                let redirect_to_tag_files = String::from("play/") + tag;
                redirect_uri.push_str("/");
                redirect_uri.push_str(&redirect_to_tag_files);
                println!("redirect now to {redirect_uri}");
                match hyper_reverse_proxy::call(client_ip, &redirect_uri, req).await {
                    Ok(response) => { Ok(response) }
                    Err(_error) => {
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap())
                    }
                }
            }
        }
    } else {
        let tag_requested = tag_extracted_option.unwrap();
        match hyper_reverse_proxy::call(client_ip, &redirect_uri, req).await {
            Ok(mut response) => {
                let mut token_map = shared.lock().unwrap();
                let token = generate_token().to_string();
                let header_value = String::from(TOKEN_NAME).add("=").add(&token);
                println!("set cookie {header_value}");
                response.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&header_value).unwrap()
                );
                if token_map.map.get(&tag_requested).is_none() {
                    let mut token_list: Vec<String> = vec!();
                    token_list.push(token);
                    token_map.map.insert(tag_requested.clone(), token_list);
                } else {
                    token_map.map.get_mut(&tag_requested).unwrap().push(token);
                }
                Ok(response)
            }
            Err(_error) => {Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())}
        }
    }
}

fn extract_cookie_map(req: &Request<Body>) -> HashMap<String, String> {
    println!("-----------------------------------------");
    let mut cookie_hashmap: HashMap<String, String> = HashMap::new();
    req.headers().iter().for_each(|(header_name, header_value)| {
        println!("{:?} {:?}", header_name, header_value);
        if header_name == "cookie" {
            cookie_hashmap = extract_cookie_values(header_value);
            cookie_hashmap.iter().for_each(|(name, value)| {
                println!("cookie value : {name} - {value}");
            });
        }
    });
    println!("-----------------------------------------");
    cookie_hashmap
}

fn find_tag_relative_to_token<'a>(token: &str, tag_token_map: &'a HashMap<String, Vec<String>>) -> Option<&'a String> {
    if let Some((tag, tokens)) = tag_token_map.iter()
        .find(|(tag, tokens)| tokens.contains(&String::from(token))) {
        Some(tag)
    } else {
        None
    }
}

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr:SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let mut token_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut shared = Arc::new(Mutex::new(
        SharedState {
            map: HashMap::new()
        }
    ));

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let shared = shared.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let shared = shared.clone();
                println!("shared state : {:?}", shared);
                handle(remote_addr, req, shared)
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Running server on {:?}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

fn generate_token() -> Uuid {
    Uuid::new_v4()
}

fn extract_tag_from_request(uri_path: &str) -> Option<String> {
    println!("match in {uri_path} ? ");
    let re = Regex::new(r"^/tag/(?<tag>[^/]+)/?$").unwrap();
    if let Some(caps) = re.captures(uri_path) {
        let str = caps.get(1).unwrap().as_str().to_string();
        println!("match");
        Some(str)
    } else {
        println!("no match!");
        None
    }
}

fn extract_cookie_values(header_value: &HeaderValue) -> HashMap<String, String> {
    let mut map = HashMap::new();
    match header_value.to_str() {
        Ok(value) => {
            String::from(value).split(";").for_each( | str | {
                let binding = String::from(str);
                let split_value = binding.split("=");
                let values: Vec <String > = split_value.into_iter().map(|v| String::from(v)).collect();
                if values.len() != 2 {
                    println ! ("can't parse cookie pair-value");
                } else {
                    map.insert(values[0].clone(), values[1].clone());
                }
            });
        }
        _ => {}
    }
    map
}

fn save_token(token: &str, tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 6379));
    let mut client = Client::connect(addr)?;

    client.set("hello", "world")?;
    client.set(token, tag)?;

    let value = client.get("hello")?.unwrap();
    println!("Hello {value}");

    let value = client.get(token)?.unwrap();
    println!("token {token} {value}");

    Ok(())
}

#[derive(Debug)]
struct SharedState {
    map: HashMap<String, Vec<String>>
}
