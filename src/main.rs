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
use app_properties::AppProperties;

/*
1. URL request dropofculture.com/tag/TAG
2. Response with index.html and cookie with TOKEN (dop_token)
3. JS request to /play with header TOKEN (dop_token)
4. playlist is sent back and then audio playback can start
 */

const TOKEN_NAME: &str = "dop_token";

fn debug_request(req: Request<Body>) -> Result<Response<Body>, Infallible>  {
    let body_str = format!("{:?}", req);
    Ok(Response::new(Body::from(body_str)))
}

async fn handle(client_ip: IpAddr, mut req: Request<Body>, shared: Arc<Mutex<HashMap<String, Vec<String>>>>, conf: Conf) -> Result<Response<Body>, Infallible> {
    let redirect_uri = &conf.redirect_uri;
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
                println!("token_map {:?}", token_map);
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
    let dop_token = req.headers().iter().find(|(header_name, header_value)| {
        // println!("{:?} {:?}", header_name, header_value);
        header_name.as_str() == "dop_token"
    }).map(|(header_name, header_value)| {header_value.to_str().unwrap_or("")})
        .unwrap_or_default();
    println!("-----------------------------------------");

    // let map = shared;
    let tag_from_token = find_tag_relative_to_token(dop_token, shared);
    if tag_from_token.is_none() {
        println!("tag_from_token not found");
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap());
    }

    
    let req_new: Request<Body> = if is_play_request(req.uri().path()) {
        //TODO put it in properties file
        let mut uri_new = String::from("http://localhost:8000/tag/");
        uri_new.push_str(tag_from_token.clone().unwrap().as_str());
        uri_new.push_str("/playlist.m3u8");
        Request::builder().uri(uri_new.as_str()).body(Body::empty()).unwrap()
    } else {
        //TODO : check that path requested is a EXTINF in playlist

        let mut uri_new = String::from("http://localhost:8000/tag/");
        uri_new.push_str(tag_from_token.clone().unwrap().as_str());
        uri_new.push_str(req.uri().path());
        Request::builder().uri(uri_new.as_str()).body(Body::empty()).unwrap()
    };

    println!("tag_from_token found {}", tag_from_token.unwrap());

    return match hyper_reverse_proxy::call(client_ip, redirect_uri, req_new).await {
        Ok(response) => {
            Ok(response)
        }
        Err(_error) => {Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap())}
    }

            /*match find_tag_relative_to_token(token, &map) {
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap());
                }
                Some(tag) => {
                    match hyper_reverse_proxy::call(client_ip, redirect_uri, req).await {
                        Ok(response) => {
                            Ok(response)
                        }
                        Err(_error) => {Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap())}
                    }
                }
            }*/

}

fn find_tag_relative_to_token(token: &str, tag_token_map: Arc<Mutex<HashMap<String, Vec<String>>>>) -> Option<String> {
    println!("find_tag_relative_to_token");
    println!("token: {}", token);
    println!("tag_token_map: {:?}", tag_token_map);
    if let Some((tag, _tokens)) = tag_token_map.lock().unwrap().iter()
        .find(|(_tag, tokens)| tokens.contains(&String::from(token))) {
        Some(String::from(tag))
    } else {
        None
    }
}

#[tokio::main]
async fn main() {
    let properties: AppProperties = AppProperties::new();
    let conf = Conf::from(properties);

    let bind_addr = &conf.bind_addr;
    let addr:SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let mut token_map: HashMap<String, Vec<String>> = HashMap::new();
    let shared = Arc::new(Mutex::new(HashMap::new()));

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let shared = shared.clone();
        let conf = conf.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let shared = shared.clone();
                let conf = conf.clone();
                handle(remote_addr, req, shared, conf)
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Running server on {:?}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

#[derive(Clone)]
struct Conf {
    redirect_uri: String,
    bind_addr: String,
}

impl From<AppProperties> for Conf {
    fn from(value: AppProperties) -> Self {
        ["redirect_uri", "bind_addr"].iter()
            .filter(|str| value.get(str).is_empty())
            .for_each(|str| {
                println!("{} is not set, can't start", str);
                std::process::exit(1);
            });
        Conf {
            redirect_uri: value.get("redirect_uri").parse().unwrap_or(String::from("http://localhost:8084")),
            bind_addr: value.get("bind_addr").parse().unwrap_or(String::from("localhost:8000")),
        }
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

fn is_play_request(uri_path: &str) -> bool {
    let re = Regex::new(r"^/play$").unwrap();
    re.is_match(uri_path)
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
