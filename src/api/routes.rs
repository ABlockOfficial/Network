use crate::api::handlers;
use crate::comms_handler::Node;
use crate::db_utils::SimpleDb;
use crate::wallet::WalletDb;

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use warp::{self, Filter};

fn with_node_component<T: Clone + Send>(
    comp: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || comp.clone())
}

//======= GET ROUTES =======//

// GET CORS
fn get_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["*"])
        .allow_methods(vec!["GET"])
}

// GET wallet info
pub fn wallet_info(
    db: WalletDb,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = get_cors();

    warp::path("wallet_info")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_wallet_info)
        .with(cors)
}

// GET all keypairs
// TODO: Requires password (will move to POST)
pub fn wallet_keypairs(
    db: WalletDb,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = get_cors();

    warp::path("wallet_keypairs")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_wallet_keypairs)
        .with(cors)
}

// GET new payment address
pub fn payment_address(
    db: WalletDb,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = get_cors();

    warp::path("new_payment_address")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_new_payment_address)
        .with(cors)
}

// GET latest block
pub fn latest_block(
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = get_cors();

    warp::path("latest_block")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_latest_block)
        .with(cors)
}

//======= POST ROUTES =======//

// POST get db item by key
pub fn blockchain_entry_by_key(
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("blockchain_entry_by_key")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_blockchain_entry_by_key)
        .with(cors)
}

// POST get block information by number
pub fn block_info_by_nums(
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("block_by_num")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_block_by_num)
        .with(cors)
}

// POST save keypair
// TODO: Requires password
pub fn import_keypairs(
    db: WalletDb,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("import_keypairs")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_import_keypairs)
        .with(cors)
}

// POST make payment
pub fn make_payment(
    db: WalletDb,
    peer: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("make_payment")
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(peer))
        .and(warp::body::json())
        .and_then(handlers::post_make_payment)
        .with(cors)
}

// POST make payment
pub fn make_ip_payment(
    db: WalletDb,
    peer: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("make_ip_payment")
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(peer))
        .and(warp::body::json())
        .and_then(handlers::post_make_ip_payment)
        .with(cors)
}

// POST request donation payment
pub fn request_donation(
    peer: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("request_donation")
        .and(warp::post())
        .and(with_node_component(peer))
        .and(warp::body::json())
        .and_then(handlers::post_request_donation)
        .with(cors)
}

// POST update running total
pub fn update_running_total(
    peer: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"]);

    warp::path("update_running_total")
        .and(warp::post())
        .and(with_node_component(peer))
        .and(warp::body::json())
        .and_then(handlers::post_update_running_total)
        .with(cors)
}

//======= NODE ROUTES =======//

pub fn user_node_routes(
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    wallet_info(db.clone())
        .or(make_payment(db.clone(), node.clone()))
        .or(make_ip_payment(db.clone(), node.clone()))
        .or(request_donation(node.clone()))
        .or(wallet_keypairs(db.clone()))
        .or(import_keypairs(db.clone()))
        .or(update_running_total(node))
        .or(payment_address(db))
}

pub fn storage_node_routes(
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    block_info_by_nums(db.clone())
        .or(latest_block(db.clone()))
        .or(blockchain_entry_by_key(db))
}
