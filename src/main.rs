use hyper::header::{ToStrError, SET_COOKIE};
use hyper::http::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::{convert::Infallible, net::SocketAddr};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use valkey::Client;

const TOKEN_NAME: &str = "dop_token";

fn debug_request(req: Request<Body>) -> Result<Response<Body>, Infallible>  {
    let body_str = format!("{:?}", req);
    Ok(Response::new(Body::from(body_str)))
}

async fn handle(client_ip: IpAddr, req: Request<Body>, shared: Arc<Mutex<HashMap<String, Vec<String>>>>) -> Result<Response<Body>, Infallible> {
    let redirect_uri = "http://127.0.0.1:8084";
    let tag_extracted_option = extract_tag_from_request(req.uri().path());
    if tag_extracted_option.is_some() {
        let tag_requested = tag_extracted_option.unwrap();
        return match hyper_reverse_proxy::call(client_ip, redirect_uri, req).await {
            Ok(mut response) => {
                println!("tag_requested not empty");
                let token = generate_token().to_string();
                response.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&*("dop_token=".to_owned() + token.as_str())).unwrap()
                );
                let mut token_map = shared.lock().unwrap();
                if token_map.get(&tag_requested).is_none() {
                    let mut token_list: Vec<String> = vec!();
                    token_list.push(token);
                    token_map.insert(tag_requested.clone(), token_list);
                } else {
                    token_map.get_mut(&tag_requested).unwrap().push(token);
                }
                Ok(response)
            }
            Err(_error) => {
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    }

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


    let mut tag_requested = String::from("");
    if cookie_hashmap.get(&String::from(TOKEN_NAME)).is_none() {
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap());
    }

    match hyper_reverse_proxy::call(client_ip, "http://127.0.0.1:8084", req).await {
        Ok(mut response) => {
            // check token
            println!("tag_requested empty");

            Ok(response)
        }
        Err(_error) => {Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap())}
    }
}

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr:SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let mut token_map: HashMap<String, Vec<String>> = HashMap::new();
    let shared = Arc::new(Mutex::new(HashMap::new()));

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let shared = shared.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let shared = shared.clone();
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
