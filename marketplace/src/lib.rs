use async_trait::async_trait;
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
pub trait Service: HaveAuthnRepository + HaveUserRepository {
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

impl<T: HaveAuthnRepository + HaveUserRepository> Service for T {}

#[derive(Error, Debug)]
pub enum CoreServiceError {
    #[error("authentication error")]
    AuthenticationError(#[from] AuthnRepositoryError),
    #[error("user error")]
    UserError(#[from] UserRepositoryError),
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
