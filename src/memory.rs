use crate::RTokenError;
use crate::models::RTokenInfo;
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// ## 日本語
///
/// 現在時刻の Unix epoch ミリ秒を返します。
///
/// ## English
///
/// Returns the current Unix epoch milliseconds.
fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}

/// ## 日本語
///
/// `now_ms + ttl_seconds` をミリ秒で安全に加算します（飽和演算）。
///
/// ## English
///
/// Computes `now_ms + ttl_seconds` in milliseconds with saturation.
fn add_ttl_ms(now_ms: u64, ttl_seconds: u64) -> u64 {
    let ttl_ms = (ttl_seconds as u128).saturating_mul(1000);
    (now_ms as u128)
        .saturating_add(ttl_ms)
        .min(u64::MAX as u128) as u64
}

/// ## 日本語
///
/// 自動掃除を実行する最小間隔（ミリ秒）。
///
/// ## English
///
/// Minimum interval for automatic pruning (milliseconds).
const PRUNE_INTERVAL_MS: u64 = 60_000;
/// ## 日本語
///
/// 自動掃除を試みる最小ストアサイズ。
///
/// ## English
///
/// Minimum store size that triggers auto-pruning.
const PRUNE_MIN_SIZE: usize = 1024;

/// ## 日本語
///
/// 認証 token の発行・保存・失効を行うマネージャです。
///
/// actix-web のアプリケーション state（例：`web::Data<RTokenManager>`）に保持する想定で、
/// 内部では `Arc<Mutex<...>>` を使って状態を共有します。そのため `Clone` は同じストアへの
/// ハンドルを増やすだけです。
///
/// token は UUID v4 文字列として生成され、次と紐づきます：
/// - ユーザー ID（`String`）
/// - 有効期限（Unix epoch ミリ秒）
///
/// ## English
///
/// Issues, stores, and revokes authentication tokens.
///
/// This type is designed to be stored in actix-web application state
/// (e.g. `web::Data<RTokenManager>`). Internally it uses an `Arc<Mutex<...>>`,
/// so `Clone` creates another handle to the same shared store.
///
/// Tokens are generated as UUID v4 strings. Each token is associated with:
/// - a user id (`String`)
/// - an expiration timestamp (Unix epoch milliseconds)
#[derive(Clone)]
pub struct RTokenManager {
    /// ## 日本語
    ///
    /// インメモリの token ストア。
    ///
    /// ## English
    ///
    /// In-memory token store.
    store: Arc<Mutex<HashMap<String, RTokenInfo>>>,
    /// ## 日本語
    ///
    /// 最後に自動掃除を実行した時刻（ミリ秒）。
    ///
    /// ## English
    ///
    /// The last time auto-pruning ran (milliseconds).
    last_prune_ms: Arc<AtomicU64>,
}

impl RTokenManager {
    /// ## 日本語
    ///
    /// 空のマネージャを作成します。
    ///
    /// ## English
    ///
    /// Creates an empty manager.
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            last_prune_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// ## 日本語
    ///
    /// 指定ユーザー ID の新しい token を発行します。
    ///
    /// `expire_time` は TTL（秒）として扱います。保存された有効期限が現在時刻より過去であれば、
    /// token は無効とみなされます。
    ///
    /// 内部 mutex が poisoned の場合は [`RTokenError::MutexPoisoned`] を返します。
    ///
    /// ## English
    ///
    /// Issues a new token for the given user id.
    ///
    /// `expire_time` is treated as TTL in seconds. The token will be considered invalid
    /// once the stored expiration timestamp is earlier than the current time.
    ///
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    pub fn login(&self, id: &str, expire_time: u64) -> Result<String, RTokenError> {
        // 日本語: token は UUID v4 文字列で生成する
        // English: Tokens are generated as UUID v4 strings
        let token = uuid::Uuid::new_v4().to_string();

        // 日本語: expire_time は秒 TTL として扱い、現在時刻から期限 (ms) を計算する
        // English: Treat expire_time as TTL seconds and compute deadline in milliseconds
        let expire_time = add_ttl_ms(now_ms(), expire_time);

        // 日本語: token と紐づく情報（user_id / expire_at / roles）を作る
        // English: Build token info (user_id / expire_at / roles)
        let info = RTokenInfo {
            user_id: id.to_string(),
            expire_at: expire_time,
            roles: Vec::new(),
        };

        // 日本語: mutex をロックしてストアに保存する（poisoned はライブラリのエラーに変換）
        // English: Lock the store mutex and insert (map poisoned to library error)
        let now_ms = now_ms();
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        store.insert(token.clone(), info);
        self.maybe_prune(&mut store, now_ms);
        Ok(token)
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// 指定ユーザー ID と役割（roles）を紐づけた新しい token を発行します（RBAC 有効時）。
    ///
    /// `expire_time` は TTL（秒）として扱います。
    ///
    /// ## English
    ///
    /// Issues a new token for the given user id and roles (RBAC enabled).
    ///
    /// `expire_time` is treated as TTL in seconds.
    pub fn login_with_roles(
        &self,
        id: &str,
        expire_time: u64,
        role: impl Into<Vec<String>>,
    ) -> Result<String, RTokenError> {
        // 日本語: token は UUID v4 文字列で生成する
        // English: Tokens are generated as UUID v4 strings
        let token = uuid::Uuid::new_v4().to_string();

        // 日本語: expire_time は秒 TTL として扱い、現在時刻から期限 (ms) を計算する
        // English: Treat expire_time as TTL seconds and compute deadline in milliseconds
        let expire_time = add_ttl_ms(now_ms(), expire_time);

        // 日本語: roles を含む token 情報を作って保存する
        // English: Build token info including roles and store it
        let info = RTokenInfo {
            user_id: id.to_string(),
            expire_at: expire_time,
            roles: role.into(),
        };
        let now_ms = now_ms();
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        store.insert(token.clone(), info);
        self.maybe_prune(&mut store, now_ms);
        Ok(token)
    }

    // pub fn set_role(&self, token: &str, role: impl Into<Vec<String>>) -> Result<(), RTokenError> {
    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// 既存 token の roles を更新します（RBAC 有効時）。
    ///
    /// token が存在しない場合でも成功として扱います（冪等）。
    ///
    /// ## English
    ///
    /// Updates roles for an existing token (RBAC enabled).
    ///
    /// This operation is idempotent: if the token does not exist, it is treated as success.
    pub fn set_roles(&self, token: &str, roles: impl Into<Vec<String>>) -> Result<(), RTokenError> {
        // 日本語: まずストアをロックする
        // English: Lock the store first
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        if let Some(info) = store.get_mut(token) {
            // 日本語: token が存在する場合のみ roles を更新する
            // English: Update roles only when the token exists
            info.roles = roles.into();
        }
        Ok(())
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token に紐づく roles を返します（RBAC 有効時）。
    ///
    /// token が存在しない場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Returns roles associated with a token (RBAC enabled).
    ///
    /// Returns `Ok(None)` if the token does not exist.
    pub fn get_roles(&self, token: &str) -> Result<Option<Vec<String>>, RTokenError> {
        // 日本語: 読み取りのためストアをロックする
        // English: Lock the store for reading
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        // 日本語: Vec を返すため clone する（ストア内部を露出しない）
        // English: Clone the Vec to avoid exposing internal storage
        Ok(store.get(token).map(|info| info.roles.clone()))
    }

    /// ## 日本語
    ///
    /// token をインメモリストアから削除して失効させます。
    ///
    /// この操作は冪等です。存在しない token を削除しても成功として扱います。
    /// 内部 mutex が poisoned の場合は [`RTokenError::MutexPoisoned`] を返します。
    ///
    /// ## English
    ///
    /// Revokes a token by removing it from the in-memory store.
    ///
    /// This operation is idempotent: removing a non-existing token is treated as success.
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    pub fn logout(&self, token: &str) -> Result<(), RTokenError> {
        // 日本語: remove は「存在しない token」でも何もしないため冪等
        // English: remove is idempotent (no-op for non-existing tokens)
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .remove(token);
        Ok(())
    }

    /// ## 日本語
    ///
    /// token に保存されている有効期限（Unix epoch ミリ秒）を返します。
    ///
    /// token が存在しない場合は `Ok(None)` を返します。本メソッドは token の期限切れ判定は
    /// 行いません。
    ///
    /// ## English
    ///
    /// Returns the stored expiration timestamp for a token (milliseconds since Unix epoch).
    ///
    /// Returns `Ok(None)` if the token does not exist. This method does not validate
    /// whether the token has already expired.
    pub fn expires_at(&self, token: &str) -> Result<Option<u64>, RTokenError> {
        // 日本語: token の存在確認のみ（期限切れ判定はしない）
        // English: Only checks existence (does not validate expiration)
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        Ok(store.get(token).map(|info| info.expire_at))
    }

    /// ## 日本語
    ///
    /// token の残り TTL（秒）を返します。
    ///
    /// 返り値：
    /// - token が存在しない：`Ok(None)`
    /// - token がすでに期限切れ：`Ok(Some(0))`（本メソッドでは削除しません）
    ///
    /// ## English
    ///
    /// Returns the remaining TTL in seconds for a token.
    ///
    /// Returns:
    /// - `Ok(None)` when the token does not exist
    /// - `Ok(Some(0))` when the token is already expired (it is not removed here)
    pub fn ttl_seconds(&self, token: &str) -> Result<Option<i64>, RTokenError> {
        // 日本語: 現在時刻 (ms) と保存された expire_at (ms) の差から残り秒数を計算する
        // English: Compute remaining seconds from now_ms and stored expire_at (milliseconds)
        let now_ms = now_ms();
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(expire_at) = store.get(token).map(|info| info.expire_at) else {
            return Ok(None);
        };

        if expire_at <= now_ms {
            return Ok(Some(0));
        }

        let remaining_ms = expire_at - now_ms;
        // 日本語: ms を秒に変換（端数は切り上げ）
        // English: Convert ms to seconds (ceil)
        let remaining_seconds = remaining_ms.div_ceil(1000) as i64;
        Ok(Some(remaining_seconds))
    }

    /// ## 日本語
    ///
    /// token の有効期限を `now + ttl_seconds` に延長します。
    ///
    /// 返り値：
    /// - token が存在し、期限切れでない：`Ok(true)`
    /// - token が存在しない、または期限切れ：`Ok(false)`（期限切れの場合は削除します）
    ///
    /// ## English
    ///
    /// Extends a token's lifetime to `now + ttl_seconds`.
    ///
    /// Returns:
    /// - `Ok(true)` if the token exists and is not expired
    /// - `Ok(false)` if the token does not exist or is expired (expired tokens are removed)
    pub fn renew(&self, token: &str, ttl_seconds: u64) -> Result<bool, RTokenError> {
        // 日本語: now + ttl_seconds で新しい expire_at (ms) を計算する
        // English: Compute new expire_at (ms) as now + ttl_seconds
        let expire_at = add_ttl_ms(now_ms(), ttl_seconds);

        // 日本語: 対象 token を更新するためストアをロックする
        // English: Lock the store to update the token
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get_mut(token) else {
            return Ok(false);
        };

        // 日本語: 期限切れは renew 失敗として扱い、ストアから削除する
        // English: Treat expired token as failure and remove it from store
        if info.expire_at < now_ms() {
            store.remove(token);
            return Ok(false);
        }

        // 日本語: 有効な token の期限を更新する
        // English: Update expiration for valid token
        info.expire_at = expire_at;
        Ok(true)
    }

    /// ## 日本語
    ///
    /// 同じユーザー（および roles）に対して新しい token を発行し、古い token を失効させます。
    ///
    /// 新しい token の TTL は「現在から `ttl_seconds`」になります。
    ///
    /// 古い token が存在しない、または期限切れの場合は `Ok(None)` を返します（期限切れの場合は
    /// 削除します）。
    ///
    /// ## English
    ///
    /// Issues a new token for the same user (and roles) and revokes the old token.
    ///
    /// The new token will have a lifetime of `ttl_seconds` from now.
    ///
    /// Returns `Ok(None)` if the old token does not exist or is expired (expired tokens
    /// are removed).
    pub fn rotate(&self, token: &str, ttl_seconds: u64) -> Result<Option<String>, RTokenError> {
        // 日本語: 新 token の期限を now + ttl_seconds で計算する
        // English: Compute new token expiration as now + ttl_seconds
        let expire_at = add_ttl_ms(now_ms(), ttl_seconds);

        // 日本語: old token の情報を参照して新 token に引き継ぐため clone する
        // English: Clone old info so we can reuse it for the new token
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get(token).cloned() else {
            return Ok(None);
        };

        // 日本語: old token が期限切れなら削除して None を返す
        // English: If old token expired, remove it and return None
        if info.expire_at < now_ms() {
            store.remove(token);
            return Ok(None);
        }

        // 日本語: 新 token を生成して情報を引き継ぐ（user_id / roles）
        // English: Generate a new token and carry over user_id / roles
        let new_token = uuid::Uuid::new_v4().to_string();
        let new_info = RTokenInfo {
            user_id: info.user_id,
            expire_at,
            roles: info.roles,
        };

        // 日本語: old token を削除し、新 token を追加する
        // English: Remove old token and insert the new token
        store.remove(token);
        store.insert(new_token.clone(), new_info);
        Ok(Some(new_token))
    }

    /// ## 日本語
    ///
    /// インメモリストアから期限切れの token を削除し、削除した件数を返します。
    ///
    /// ## English
    ///
    /// Removes expired tokens from the in-memory store and returns how many were removed.
    pub fn prune_expired(&self) -> Result<usize, RTokenError> {
        // 日本語: retain を使って期限切れのエントリを一括削除する
        // English: Use retain to bulk-remove expired entries
        let now = now_ms();
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;

        let original_len = store.len();
        store.retain(|_token, info| info.expire_at >= now);
        Ok(original_len - store.len())
    }

    /// ## 日本語
    ///
    /// token を検証し、有効であれば紐づくユーザー ID を返します。
    ///
    /// 振る舞い：
    /// - token が存在し、期限切れでない：`Ok(Some(user_id))`
    /// - token が存在しない、または期限切れ：`Ok(None)`
    /// - 期限切れ token は検証時にストアから削除されます
    ///
    /// ## English
    ///
    /// Validates a token and returns the associated user id if present.
    ///
    /// Behavior:
    /// - Returns `Ok(Some(user_id))` when the token exists and is not expired.
    /// - Returns `Ok(None)` when the token does not exist or is expired.
    /// - Expired tokens are removed from the in-memory store during validation.
    pub fn validate(&self, token: &str) -> Result<Option<String>, RTokenError> {
        #[cfg(feature = "rbac")]
        {
            Ok(self
                .validate_with_roles(token)?
                .map(|(user_id, _roles)| user_id))
        }

        #[cfg(not(feature = "rbac"))]
        {
            // 日本語: 検証時は期限切れを掃除するため書き込みロックを取る
            // English: Take a write lock so we can remove expired tokens during validation
            let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
            let Some(info) = store.get(token) else {
                return Ok(None);
            };

            // 日本語: 期限切れなら削除して無効扱いにする
            // English: If expired, remove and treat as invalid
            if info.expire_at < now_ms() {
                store.remove(token);
                return Ok(None);
            }

            // 日本語: 有効 token の user_id を返す
            // English: Return user_id for a valid token
            Ok(Some(info.user_id.clone()))
        }
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token を検証し、ユーザー ID と roles を返します（RBAC 有効時）。
    ///
    /// 期限切れの扱いは [`RTokenManager::validate`] と同じです。
    ///
    /// ## English
    ///
    /// Validates a token and returns both user id and roles (RBAC enabled).
    ///
    /// This has the same expiration behavior as [`RTokenManager::validate`].
    pub fn validate_with_roles(
        &self,
        token: &str,
    ) -> Result<Option<(String, Vec<String>)>, RTokenError> {
        // 日本語: 検証時に期限切れの削除があり得るため書き込みロックを取る
        // English: Take a write lock because we may remove expired tokens
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get(token) else {
            return Ok(None);
        };

        // 日本語: 期限切れなら削除して無効扱いにする
        // English: If expired, remove and treat as invalid
        if info.expire_at < now_ms() {
            store.remove(token);
            return Ok(None);
        }

        // 日本語: user_id と roles を返す（clone して内部を露出しない）
        // English: Return user_id and roles (clone to avoid exposing internals)
        Ok(Some((info.user_id.clone(), info.roles.clone())))
    }

    /// ## 日本語
    ///
    /// 条件を満たす場合のみ期限切れ token を掃除します。
    ///
    /// ## English
    ///
    /// Prunes expired tokens only when the thresholds are met.
    fn maybe_prune(&self, store: &mut HashMap<String, RTokenInfo>, now_ms: u64) {
        if store.len() < PRUNE_MIN_SIZE {
            return;
        }

        let last = self.last_prune_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < PRUNE_INTERVAL_MS {
            return;
        }

        self.last_prune_ms.store(now_ms, Ordering::Relaxed);
        store.retain(|_token, info| info.expire_at >= now_ms);
    }
}

impl Default for RTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

/// ## 日本語
///
/// actix-web / axum から抽出される認証済みユーザーコンテキストです。
///
/// 抽出が成功した場合：
/// - `id` は [`RTokenManager::login`] に渡したユーザー ID
/// - `token` はリクエストに含まれていた token の生文字列
///
/// token は `Authorization` header から読み取ります。次の形式に対応します：
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
///
/// ## English
///
/// An authenticated request context extracted from actix-web / axum.
///
/// If extraction succeeds, `id` is the user id previously passed to
/// [`RTokenManager::login`], and `token` is the original token from the request.
///
/// The token is read from `Authorization` header. Both of the following formats
/// are accepted:
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
#[cfg(any(feature = "actix", feature = "axum"))]
#[derive(Debug)]
pub struct RUser {
    /// ## 日本語
    ///
    /// token に紐づくユーザー ID。
    ///
    /// ## English
    ///
    /// The user id associated with the token.
    pub id: String,

    /// ## 日本語
    ///
    /// リクエストに含まれていた token の生文字列。
    ///
    /// ## English
    ///
    /// The raw token string from the request.
    pub token: String,
    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token に紐づく roles（RBAC 有効時）。
    ///
    /// ## English
    ///
    /// Roles associated with the token (RBAC enabled).
    pub roles: Vec<String>,
}

#[cfg(feature = "rbac")]
impl RUser {
    /// ## 日本語
    ///
    /// 指定した role を持つかどうかを返します。
    ///
    /// ## English
    ///
    /// Returns whether the user has the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// ## 日本語
///
/// actix-web のリクエストから [`RUser`] を抽出します。
///
/// 失敗時：
/// - 500：`app_data` にマネージャが無い、または mutex が poisoned
/// - 401：token が無い／無効／期限切れ
///
/// ## English
///
/// Extracts [`RUser`] from an actix-web request.
///
/// Failure modes:
/// - 500: manager is missing from `app_data`, or mutex is poisoned
/// - 401: token is missing, invalid, or expired
#[cfg(feature = "actix")]
impl actix_web::FromRequest for RUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        use actix_web::web;

        let manager = match req.app_data::<web::Data<RTokenManager>>() {
            Some(m) => m.clone(),
            None => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorInternalServerError(
                        "Token manager not found",
                    ))
                });
            }
        };
        let token = match crate::extract_token_from_request(req) {
            Some(token) => token,
            None => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
                });
            }
        };

        Box::pin(async move {
            #[cfg(feature = "rbac")]
            {
                let token_for_check = token.clone();
                let manager = manager.clone();
                let user_info = actix_web::rt::task::spawn_blocking(move || {
                    manager.validate_with_roles(&token_for_check)
                })
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
                .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?;

                if let Some((user_id, roles)) = user_info {
                    return Ok(RUser {
                        id: user_id,
                        token,
                        roles,
                    });
                }

                Err(actix_web::error::ErrorUnauthorized("Invalid token"))
            }

            #[cfg(not(feature = "rbac"))]
            {
                let token_for_check = token.clone();
                let manager = manager.clone();
                let user_id =
                    actix_web::rt::task::spawn_blocking(move || manager.validate(&token_for_check))
                        .await
                        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
                        .map_err(|_| {
                            actix_web::error::ErrorInternalServerError("Mutex poisoned")
                        })?;

                if let Some(user_id) = user_id {
                    return Ok(RUser { id: user_id, token });
                }

                Err(actix_web::error::ErrorUnauthorized("Invalid token"))
            }
        })
    }
}
