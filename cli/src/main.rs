use marketplace::{
    ConfirmAuthCodeEmailCommand, Context, SendAuthCodeEmailCommand, Service, SessionID,
    StartSessionCommand,
};

#[tokio::main]
async fn main() {
    let context =
        Context::new("postgres://postgres:duf3QMY!tma!dfp3wcp@35.221.167.63/postgres").unwrap();
    // let session_id = context.start_session(StartSessionCommand {}).await.unwrap();
    // let command = SendAuthCodeEmailCommand {
    //     to: String::from("me@n-u.kr"),
    //     session_id,
    // };
    // context.send_auth_code_email(command).await.unwrap();
    let command = ConfirmAuthCodeEmailCommand {
        session_id: SessionID::parse("ecbff5dc-a763-4772-b194-c6a5ec310a6c").unwrap(),
        code: String::from("pQy08v"),
    };
    context.confirm_auth_code_email(command).await.unwrap();
    println!("Hello, world!");
}
