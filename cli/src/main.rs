use marketplace::{Context, SendAuthCodeEmailCommand, Service};

#[tokio::main]
async fn main() {
    let context =
        Context::new("postgres://postgres:duf3QMY!tma!dfp3wcp@35.221.167.63/postgres").unwrap();
    let command = SendAuthCodeEmailCommand {
        to: String::from("me@n-u.kr"),
    };
    context.send_auth_code_email(command).await.unwrap();
    println!("Hello, world!");
}
