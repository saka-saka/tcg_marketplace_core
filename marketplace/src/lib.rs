use async_trait::async_trait;
use domain::{Code, EmailAddress, EmailCode};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use thiserror::Error;
use uuid::Uuid;

pub struct UserID(String);
pub struct SessionID(String);
impl SessionID {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
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
    async fn save_email_code(&self, email_code: EmailCode) -> Result<(), AuthnRepositoryError>;
    async fn save_email_session(
        &self,
        email: EmailAddress,
        session_id: SessionID,
    ) -> Result<(), AuthnRepositoryError>;
    async fn get_email_code(
        &self,
        session_id: SessionID,
    ) -> Result<EmailCode, AuthnRepositoryError>;
}

pub trait HaveAuthnRepository {
    type Repository: AuthnRepository + Sync;
    fn provide_authn_repository(&self) -> &Self::Repository;
}

#[async_trait]
pub trait UserRepository {
    async fn retrive_user(&self, user_id: Uuid) -> Result<Option<User>, UserRepositoryError>;
    async fn create_user(&self, email: EmailAddress) -> Result<(), UserRepositoryError>;
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
    pub session_id: SessionID,
}
pub struct ConfirmAuthCodeEmailCommand {
    pub session_id: SessionID,
    pub code: String,
}

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
        let authn_repo = self.provide_authn_repository();
        let setting_repo = self.provide_setting_repository();
        let send_grid_api_key = setting_repo
            .retrive_setting(SettingKey::SendGridApiKey)
            .await
            .unwrap()
            .unwrap();
        let email_code = EmailCode::from_email(&command.to).unwrap();
        authn_repo
            .save_email_code(email_code.clone())
            .await
            .unwrap();
        authn_repo
            .save_email_session(email_code.get_address(), command.session_id)
            .await
            .unwrap();
        let mailer = sendgrid::SendGrid::new(&send_grid_api_key);
        mailer.send_mail_code(email_code).await;
        Ok(())
    }
    async fn confirm_auth_code_email(
        &self,
        command: ConfirmAuthCodeEmailCommand,
    ) -> Result<(), CoreServiceError> {
        let authn_repo = self.provide_authn_repository();
        let email_code = authn_repo.get_email_code(command.session_id).await.unwrap();
        if email_code.confirm_code(&command.code) {
            let user_repo = self.provide_user_repository();
            user_repo
                .create_user(email_code.get_address())
                .await
                .unwrap();
        } else {
            return Err(CoreServiceError::AuthenticationError(
                AuthnRepositoryError::Unauthenticated,
            ));
        }
        Ok(())
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
    async fn save_email_code(&self, email_code: EmailCode) -> Result<(), AuthnRepositoryError> {
        sqlx::query!(
            "INSERT INTO email_auth_code(email, code) VALUES($1, $2)",
            &email_code.get_address().0,
            email_code.get_code()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn save_email_session(
        &self,
        email: EmailAddress,
        session_id: SessionID,
    ) -> Result<(), AuthnRepositoryError> {
        sqlx::query!(
            "INSERT INTO email_session(email, session_id) VALUES($1, $2)",
            &email.0,
            session_id.to_uuid()?
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn get_email_code(
        &self,
        session_id: SessionID,
    ) -> Result<EmailCode, AuthnRepositoryError> {
        let record = sqlx::query!("SELECT eac.email, eac.code FROM email_auth_code AS eac LEFT JOIN email_session ON email_session.session_id = $1", session_id.to_uuid().unwrap()).fetch_one(&self.pool).await.unwrap();
        Ok(EmailCode {
            email: EmailAddress(record.email),
            code: Code(record.code),
        })
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
    async fn create_user(&self, email: EmailAddress) -> Result<(), UserRepositoryError> {
        sqlx::query!(
            "INSERT INTO users(id, username, email) VALUES(gen_random_uuid(), 'unnamed', $1)",
            &email.0
        )
        .execute(&self.pool)
        .await
        .unwrap();
        Ok(())
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
        from: SenderData,
        subject: String,
        content: Vec<EmailContent>,
    }

    #[derive(Serialize)]
    pub struct SenderData {
        email: EmailAddress,
    }

    #[derive(Serialize)]
    pub struct EmailContent {
        r#type: String,
        value: String,
    }

    #[derive(Serialize)]
    pub struct Personalization {
        to: Vec<To>,
    }

    #[derive(Serialize)]
    pub struct To {
        email: EmailAddress,
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
                    to: vec![To {
                        email: email_code.get_address(),
                    }],
                }],
                from: SenderData {
                    email: EmailAddress::parse("noreply@tcgbuysell.com").unwrap(),
                },
                subject: String::from("Sign in to TCG Marketplace"),
                content: vec![EmailContent {
                    r#type: "text/plain".to_string(),
                    value: String::from(email_code.get_code()),
                }],
            };
            let json_data = serde_json::to_string(&data).unwrap();
            println!("{json_data}");
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
            println!("{:?}", result);
        }
    }
}
mod domain {
    use rand::{distributions::Alphanumeric, Rng};
    use serde::Serialize;
    use thiserror::Error;

    #[derive(Clone)]
    pub struct EmailCode {
        pub(crate) email: EmailAddress,
        pub(crate) code: Code,
    }

    impl EmailCode {
        pub fn from_email(email: &str) -> Result<Self, AuthnError> {
            let email = EmailAddress::parse(email)?;
            Ok(Self {
                email,
                code: Code::new(),
            })
        }
        pub fn confirm_code(&self, code: &str) -> bool {
            self.code.confirm(code)
        }
        pub fn get_address(&self) -> EmailAddress {
            self.email.clone()
        }
        pub fn get_code(&self) -> &str {
            &self.code.get_code()
        }
    }

    #[derive(Serialize, Clone)]
    pub struct EmailAddress(pub(crate) String);

    impl EmailAddress {
        pub fn parse(s: &str) -> Result<Self, AuthnError> {
            Ok(Self(s.to_string()))
        }
    }

    #[derive(Clone)]
    pub(crate) struct Code(pub(crate) String);
    impl Code {
        fn new() -> Self {
            let rand_str: String = rand::thread_rng()
                .sample_iter(Alphanumeric)
                .take(6)
                .map(char::from)
                .collect();
            Self(rand_str)
        }
        fn confirm(&self, code: &str) -> bool {
            code.to_string() == self.0
        }
        fn get_code(&self) -> &str {
            &self.0
        }
    }

    #[derive(Debug, Error)]
    pub enum AuthnError {}
}
