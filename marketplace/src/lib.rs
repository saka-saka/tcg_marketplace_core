use async_trait::async_trait;
use domain::{EmailAddress, EmailCode, EmailCodeBuilder};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use thiserror::Error;
use uuid::Uuid;

pub struct UserID(String);
impl From<Uuid> for UserID {
    fn from(value: Uuid) -> Self {
        Self(value.to_string())
    }
}
impl ToString for UserID {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone)]
pub struct SessionID(Uuid);
impl SessionID {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
    fn to_uuid(&self) -> &Uuid {
        &self.0
    }
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        let sid = Uuid::parse_str(s)?;
        Ok(Self(sid))
    }
}

impl ToString for SessionID {
    fn to_string(&self) -> String {
        self.0.to_string()
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
    async fn get_email_code(&self, sid: &SessionID) -> Result<EmailCode, AuthnRepositoryError>;
    async fn get_email(
        &self,
        sid: &SessionID,
    ) -> Result<Option<EmailAddress>, AuthnRepositoryError>;
    async fn delete_email_code(&self, session_id: SessionID) -> Result<(), AuthnRepositoryError>;
    async fn create_session(&self) -> Result<SessionID, AuthnRepositoryError>;
    async fn update_session(&self, user_id: UserID) -> Result<(), AuthnRepositoryError>;
}

pub trait HaveAuthnRepository {
    type Repository: AuthnRepository + Sync;
    fn provide_authn_repository(&self) -> &Self::Repository;
}

#[async_trait]
pub trait UserRepository {
    async fn retrive_user(&self, user_id: Uuid) -> Result<Option<User>, UserRepositoryError>;
    async fn create_user(&self, email: EmailAddress) -> Result<UserID, UserRepositoryError>;
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

pub struct StartSessionCommand {}

impl StartSessionCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
pub trait Service: HaveAuthnRepository + HaveUserRepository + HaveSettingRepository {
    async fn start_session(
        &self,
        _command: StartSessionCommand,
    ) -> Result<SessionID, CoreServiceError> {
        let authn_repo = self.provide_authn_repository();
        let session_id = authn_repo.create_session().await?;
        Ok(session_id)
    }
    // if the email has been registered for this session, update it.
    async fn send_auth_code_email(
        &self,
        command: SendAuthCodeEmailCommand,
    ) -> Result<(), CoreServiceError> {
        let authn_repo = self.provide_authn_repository();
        let email_code = EmailCodeBuilder::new()
            .session_id(command.session_id)
            .email_address(&command.to)
            .build()
            .unwrap();
        authn_repo.save_email_code(email_code.clone()).await?;
        let setting_repo = self.provide_setting_repository();
        let send_grid_api_key = setting_repo
            .retrive_setting(SettingKey::SendGridApiKey)
            .await?
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
        let email_code = authn_repo.get_email_code(&command.session_id).await?;
        if email_code.confirm_code(&command.code) {
            let user_repo = self.provide_user_repository();
            let user_id = user_repo.create_user(email_code.get_address()).await?;
            authn_repo.update_session(user_id).await?;
            authn_repo.delete_email_code(command.session_id).await?;
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
        let user = user_repo.retrive_user(user_id).await?.unwrap();
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
        let record = sqlx::query!(
            "SELECT user_id FROM sessions WHERE id = $1",
            session_id.to_uuid()
        )
        .fetch_one(&self.pool)
        .await?;
        let user_id = record
            .user_id
            .ok_or(AuthnRepositoryError::Unauthenticated)?;
        Ok(user_id)
    }
    async fn save_email_code(&self, email_code: EmailCode) -> Result<(), AuthnRepositoryError> {
        sqlx::query!(
            "INSERT INTO email_auth_code(email, code, session_id) VALUES($1, $2, $3)",
            &email_code.get_address().0,
            email_code.get_code(),
            email_code.session_id.to_uuid(),
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn get_email_code(&self, sid: &SessionID) -> Result<EmailCode, AuthnRepositoryError> {
        let record = sqlx::query!("SELECT eac.email, eac.code FROM email_auth_code AS eac LEFT JOIN email_session ON email_session.session_id = $1", sid.to_uuid()).fetch_one(&self.pool).await?;
        let email_code = EmailCodeBuilder::new()
            .email_address(&record.email)
            .session_id(sid.clone())
            .code(&record.code)
            .build()
            .unwrap();
        Ok(email_code)
    }
    async fn get_email(
        &self,
        sid: &SessionID,
    ) -> Result<Option<EmailAddress>, AuthnRepositoryError> {
        let record = sqlx::query!(
            "SELECT email from email_session WHERE session_id = $1",
            sid.to_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;
        let email = record
            .ok_or_else(|| AuthnRepositoryError::Unauthenticated)?
            .email;
        let email_addr = EmailAddress::parse(&email).unwrap();
        Ok(Some(email_addr))
    }
    async fn create_session(&self) -> Result<SessionID, AuthnRepositoryError> {
        let sid = SessionID::new();
        sqlx::query!("INSERT INTO sessions(id) VALUES($1)", sid.to_uuid())
            .execute(&self.pool)
            .await?;
        Ok(sid)
    }
    async fn update_session(&self, user_id: UserID) -> Result<(), AuthnRepositoryError> {
        let uid = Uuid::parse_str(&user_id.to_string())?;
        sqlx::query!("UPDATE sessions SET user_id = $1 WHERE id = (SELECT email_auth_code.session_id FROM email_auth_code LEFT JOIN users ON users.email = email_auth_code.email WHERE users.id = $1)", uid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn delete_email_code(&self, session_id: SessionID) -> Result<(), AuthnRepositoryError> {
        sqlx::query!(
            "DELETE FROM email_auth_code WHERE session_id = $1",
            session_id.to_uuid()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
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
    async fn create_user(&self, email: EmailAddress) -> Result<UserID, UserRepositoryError> {
        let result = sqlx::query!(
            "INSERT INTO users(id, username, email) VALUES(gen_random_uuid(), 'unnamed', $1) ON CONFLICT(email) DO NOTHING RETURNING id",
            &email.0
        ).fetch_optional(&self.pool).await?;
        let id = match result {
            Some(record) => record.id,
            None => {
                sqlx::query!("SELECT id FROM users WHERE email = $1", &email.0)
                    .fetch_one(&self.pool)
                    .await?
                    .id
            }
        };
        Ok(id.into())
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

    use crate::SessionID;

    #[derive(Clone)]
    pub struct EmailCode {
        pub(crate) email_address: EmailAddress,
        pub(crate) code: Code,
        pub(crate) session_id: SessionID,
    }

    pub struct EmailCodeBuilder {
        pub(crate) email_address: Option<String>,
        pub(crate) session_id: Option<SessionID>,
        pub(crate) code: Option<String>,
    }

    impl EmailCodeBuilder {
        pub(crate) fn new() -> Self {
            Self {
                email_address: None,
                session_id: None,
                code: None,
            }
        }
        pub(crate) fn email_address(self, email_address: &str) -> Self {
            Self {
                email_address: Some(email_address.to_string()),
                session_id: self.session_id,
                code: self.code,
            }
        }
        pub(crate) fn session_id(self, session_id: SessionID) -> Self {
            Self {
                email_address: self.email_address,
                code: self.code,
                session_id: Some(session_id),
            }
        }
        pub(crate) fn code(self, code: &str) -> Self {
            Self {
                email_address: self.email_address,
                code: Some(code.to_string()),
                session_id: self.session_id,
            }
        }
        pub(crate) fn build(self) -> Result<EmailCode, EmailCodeBuilderError> {
            let email_address = self
                .email_address
                .ok_or_else(|| EmailCodeBuilderError::Unknown)?;
            let email_address = EmailAddress::parse(&email_address)?;
            let code = match self.code {
                Some(c) => Code(c),
                None => Code::new(),
            };
            let session_id = self
                .session_id
                .ok_or_else(|| EmailCodeBuilderError::Unknown)?;
            Ok(EmailCode {
                email_address,
                code,
                session_id,
            })
        }
    }

    #[derive(Error, Debug)]
    pub enum EmailCodeBuilderError {
        #[error("unknown error")]
        Unknown,
        #[error("authn error")]
        AuthnError(#[from] AuthnError),
    }

    impl EmailCode {
        pub fn confirm_code(&self, code: &str) -> bool {
            self.code.confirm(code)
        }
        pub fn get_address(&self) -> EmailAddress {
            self.email_address.clone()
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

    impl ToString for EmailAddress {
        fn to_string(&self) -> String {
            self.0.clone()
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
