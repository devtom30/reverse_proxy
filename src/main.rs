use hyper::header::{ToStrError, SET_COOKIE};
use hyper::http::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::{convert::Infallible, net::SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use mongodb::{
    bson::doc,
    Client,
    Collection
};
use mongodb::bson::DateTime;
use serde::Serialize;

const TOKEN_NAME: &str = "dop_token";

fn debug_request(req: Request<Body>) -> Result<Response<Body>, Infallible>  {
    let body_str = format!("{:?}", req);
    Ok(Response::new(Body::from(body_str)))
}

async fn handle(
    client_ip: IpAddr,
    req: Request<Body>,
    shared: Arc<Mutex<HashMap<String, Vec<String>>>>,
    db_client: Arc<Client>,
) -> Result<Response<Body>, Infallible> {
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
                    token_list.push(token.clone());
                    token_map.insert(tag_requested.clone(), token_list);
                } else {
                    token_map.get_mut(&tag_requested).unwrap().push(token.clone());
                }
                save_token(db_client.clone(), &token, &tag_requested).await
                    .expect(&format!("can't save token {} for tag {}", token, tag_requested));
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

    let token_found = match cookie_hashmap.get(&String::from(TOKEN_NAME)) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap());
        }
        Some(token) => {
            token
        }
    };

    // let map = shared;
    let tag_from_token = find_tag_relative_to_token(token_found, shared);
    if tag_from_token.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap());
    }

    return match hyper_reverse_proxy::call(client_ip, redirect_uri, req).await {
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
    if let Some((tag, tokens)) = tag_token_map.lock().unwrap().iter()
        .find(|(tag, tokens)| tokens.contains(&String::from(token))) {
        Some(String::from(tag))
    } else {
        None
    }
}

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr:SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let mut token_map: HashMap<String, Vec<String>> = HashMap::new();
    let shared = Arc::new(Mutex::new(HashMap::new()));

    let uri = "mongodb://localhost:27017/";
    let db_client = Arc::new(
        Client::with_uri_str(uri).await.expect("MongoDB client creation failed"));

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let shared = shared.clone();
        let db_client = db_client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let shared = shared.clone();
                let db_client = db_client.clone();
                handle(remote_addr, req, shared, db_client)
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

async fn save_token(client: Arc<Client>, token: &str, tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    let my_coll: Collection<TagToken> = client
        .database("dropofculture")
        .collection("token");
    let insert_doc = TagToken {
        tag: tag.to_string(),
        token: token.to_string(),
        date_time: DateTime::now()
    };

    let res = my_coll.insert_one(insert_doc).await?;
    println!("Inserted a document with _id: {}", res.inserted_id);

    Ok(())
}

#[derive(Serialize)]
struct TagToken {
    tag: String,
    token: String,
    date_time: DateTime
}

impl TagToken {}
