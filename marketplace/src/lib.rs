use async_trait::async_trait;
use domain::EmailCode;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use thiserror::Error;
use uuid::Uuid;

pub struct UserID(String);
pub struct SessionID(String);
impl SessionID {
    fn to_uuid(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.0)
    }
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s)?;
        Ok(Self(s.to_owned()))
    }
}
pub struct User {
    pub id: Uuid,
    pub name: String,
}

#[async_trait]
pub trait AuthnRepository {
    async fn auth(&self, session_id: SessionID) -> Result<Uuid, AuthnRepositoryError>;
}

pub trait HaveAuthnRepository {
    type Repository: AuthnRepository + Sync;
    fn provide_authn_repository(&self) -> &Self::Repository;
}

#[async_trait]
pub trait UserRepository {
    async fn retrive_user(&self, user_id: Uuid) -> Result<Option<User>, UserRepositoryError>;
    async fn update_username(
        &self,
        user_id: Uuid,
        username: String,
    ) -> Result<(), UserRepositoryError>;
}

pub trait HaveUserRepository {
    type Repository: UserRepository + Sync;
    fn provide_user_repository(&self) -> &Self::Repository;
}

#[async_trait]
pub trait SettingRepository {
    async fn retrive_setting(
        &self,
        key: SettingKey,
    ) -> Result<Option<String>, SettingRepositoryError>;
}

pub trait HaveSettingRepository {
    type Repository: SettingRepository + Sync;
    fn provide_setting_repository(&self) -> &Self::Repository;
}

pub struct SendAuthCodeEmailCommand {
    pub to: String,
}
pub struct ComfirmAuthCodeEmailCommand {}

pub enum SettingKey {
    SendGridApiKey,
}

impl ToString for SettingKey {
    fn to_string(&self) -> String {
        match self {
            SettingKey::SendGridApiKey => "send_grid_api_key".to_string(),
        }
    }
}

#[async_trait]
pub trait Service: HaveAuthnRepository + HaveUserRepository + HaveSettingRepository {
    async fn send_auth_code_email(
        &self,
        command: SendAuthCodeEmailCommand,
    ) -> Result<(), CoreServiceError> {
        let setting_repo = self.provide_setting_repository();
        let send_grid_api_key = setting_repo
            .retrive_setting(SettingKey::SendGridApiKey)
            .await
            .unwrap()
            .unwrap();
        let mailer = sendgrid::SendGrid::new(&send_grid_api_key);
        mailer
            .send_mail_code(EmailCode::from_email(&command.to).unwrap())
            .await;
        Ok(())
    }
    async fn comfirm_auth_code_email(
        &self,
        _command: ComfirmAuthCodeEmailCommand,
    ) -> Result<(), CoreServiceError> {
        unimplemented!()
    }
    async fn get_user(&self, session_id: SessionID) -> Result<User, CoreServiceError> {
        let authn_repo = self.provide_authn_repository();
        let user_id = authn_repo.auth(session_id).await?;
        let user_repo = self.provide_user_repository();
        let user = user_repo.retrive_user(user_id).await.unwrap().unwrap();
        Ok(user)
    }

    async fn update_user(
        &self,
        session_id: SessionID,
        username: String,
    ) -> Result<(), CoreServiceError> {
        let authn_repo = self.provide_authn_repository();
        let user_id = authn_repo.auth(session_id).await?;
        let user_repo = self.provide_user_repository();
        user_repo.update_username(user_id, username).await?;
        Ok(())
    }
}

impl<T: HaveAuthnRepository + HaveUserRepository + HaveSettingRepository> Service for T {}

#[derive(Error, Debug)]
pub enum CoreServiceError {
    #[error("authentication error")]
    AuthenticationError(#[from] AuthnRepositoryError),
    #[error("user error")]
    UserError(#[from] UserRepositoryError),
    #[error("setting error")]
    SettingError(#[from] SettingRepositoryError),
}

#[derive(Error, Debug)]
pub enum AuthnRepositoryError {
    #[error("Uuid parse error")]
    UUIDParseError(#[from] uuid::Error),
    #[error("SQLx error")]
    SQLxError(#[from] sqlx::Error),
    #[error("Unauthenticated")]
    Unauthenticated,
}

#[derive(Error, Debug)]
pub enum UserRepositoryError {
    #[error("Uuid parse error")]
    UUIDParseError(#[from] uuid::Error),
    #[error("SQLx error")]
    SQLxError(#[from] sqlx::Error),
    #[error("Unauthenticated")]
    Unauthenticated,
}

#[derive(Error, Debug)]
pub enum SettingRepositoryError {
    #[error("Uuid parse error")]
    UUIDParseError(#[from] uuid::Error),
    #[error("SQLx error")]
    SQLxError(#[from] sqlx::Error),
    #[error("Unauthenticated")]
    Unauthenticated,
}

pub struct Context {
    pool: Pool<Postgres>,
}

impl Context {
    pub fn new(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPoolOptions::new().max_connections(5).connect_lazy(url)?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl AuthnRepository for Context {
    async fn auth(&self, session_id: SessionID) -> Result<Uuid, AuthnRepositoryError> {
        let sid = session_id.to_uuid()?;
        let record = sqlx::query!("SELECT user_id FROM sessions WHERE id = $1", sid)
            .fetch_one(&self.pool)
            .await?;
        let user_id = record
            .user_id
            .ok_or(AuthnRepositoryError::Unauthenticated)?;
        Ok(user_id)
    }
}

#[async_trait]
impl UserRepository for Context {
    async fn retrive_user(&self, user_id: Uuid) -> Result<Option<User>, UserRepositoryError> {
        let record = sqlx::query!("SELECT username FROM users WHERE id = $1", user_id)
            .fetch_one(&self.pool)
            .await?;
        let user = record.username.map(|username| User {
            id: user_id,
            name: username,
        });
        Ok(user)
    }
    async fn update_username(
        &self,
        user_id: Uuid,
        username: String,
    ) -> Result<(), UserRepositoryError> {
        sqlx::query!(
            "UPDATE users SET username = $1 WHERE id = $2",
            username,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl SettingRepository for Context {
    async fn retrive_setting(
        &self,
        key: SettingKey,
    ) -> Result<Option<String>, SettingRepositoryError> {
        let record = sqlx::query!("SELECT v FROM settings WHERE k = $1", key.to_string())
            .fetch_one(&self.pool)
            .await?;
        let v = record.v;
        Ok(Some(v))
    }
}

impl HaveUserRepository for Context {
    type Repository = Context;
    fn provide_user_repository(&self) -> &Self::Repository {
        self
    }
}
impl HaveAuthnRepository for Context {
    type Repository = Context;
    fn provide_authn_repository(&self) -> &Self::Repository {
        self
    }
}

impl HaveSettingRepository for Context {
    type Repository = Context;
    fn provide_setting_repository(&self) -> &Self::Repository {
        self
    }
}

mod sendgrid {
    use reqwest::{
        header::{HeaderMap, HeaderValue, AUTHORIZATION},
        Method,
    };
    use serde::Serialize;

    use crate::domain::{EmailAddress, EmailCode};

    #[derive(Serialize)]
    pub struct SendEmailData {
        personalizations: Vec<Personalization>,
    }

    #[derive(Serialize)]
    pub struct SenderData {
        email: EmailAddress,
        subject: String,
        content: Vec<EmailContent>,
    }

    #[derive(Serialize)]
    pub struct EmailContent {
        r#type: String,
        value: String,
    }

    #[derive(Serialize)]
    pub struct Personalization {
        to: Vec<String>,
        from: SenderData,
    }

    pub struct SendGrid {
        key: String,
    }

    impl SendGrid {
        pub fn new(key: &str) -> Self {
            Self {
                key: key.to_string(),
            }
        }
        pub async fn send_mail_code(&self, email_code: EmailCode) {
            let url = "https://api.sendgrid.com/v3/mail/send";
            let data = SendEmailData {
                personalizations: vec![Personalization {
                    to: vec![email_code.get_address().to_string()],
                    from: SenderData {
                        email: EmailAddress::parse("noreply@tcgbuysell.com").unwrap(),
                        subject: String::from("Sign in to TCG Marketplace"),
                        content: vec![EmailContent {
                            r#type: "text/plain".to_string(),
                            value: String::from(email_code.get_code()),
                        }],
                    },
                }],
            };
            let json_data = serde_json::to_string(&data).unwrap();
            let client = reqwest::Client::new();
            let mut headers = HeaderMap::new();
            let authorization_value =
                HeaderValue::from_str(&format!("Bearer {}", self.key)).unwrap();
            headers.insert(AUTHORIZATION, authorization_value);
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            let result = client
                .request(Method::POST, url)
                .headers(headers)
                .body(json_data)
                .send()
                .await
                .unwrap();
        }
    }
}
mod domain {
    use rand::{distributions::Alphanumeric, Rng};
    use serde::Serialize;
    use thiserror::Error;

    pub struct EmailCode {
        email: EmailAddress,
        code: Code,
    }

    impl EmailCode {
        pub fn from_email(email: &str) -> Result<Self, AuthnError> {
            let email = EmailAddress::parse(email)?;
            Ok(Self {
                email,
                code: Code::new(),
            })
        }
        pub fn comfirm_code(&self, code: &str) -> bool {
            self.code.comfirm(code)
        }
        pub fn get_address(&self) -> &str {
            &self.email.0
        }
        pub fn get_code(&self) -> &str {
            &self.code.get_code()
        }
    }

    #[derive(Serialize)]
    pub struct EmailAddress(String);

    impl EmailAddress {
        pub fn parse(s: &str) -> Result<Self, AuthnError> {
            Ok(Self(s.to_string()))
        }
    }
    struct Code(String);
    impl Code {
        fn new() -> Self {
            let rand_str: String = rand::thread_rng()
                .sample_iter(Alphanumeric)
                .take(6)
                .map(char::from)
                .collect();
            Self(rand_str)
        }
        fn comfirm(&self, code: &str) -> bool {
            code.to_string() == self.0
        }
        fn get_code(&self) -> &str {
            &self.0
        }
    }

    #[derive(Debug, Error)]
    pub enum AuthnError {}
}
