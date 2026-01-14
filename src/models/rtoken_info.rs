/// Token metadata stored in memory.
///
/// This is an internal record associated with a token string.
///
/// ## 繁體中文
///
/// 儲存在記憶體中的 token 中繼資料。
///
/// 這是與 token 字串綁定的內部紀錄。
#[derive(Clone)]
#[cfg_attr(feature = "rbac", derive(serde::Serialize, serde::Deserialize))]
pub struct RTokenInfo {
    /// User id associated with the token.
    ///
    /// ## 繁體中文
    ///
    /// 與 token 綁定的使用者 id。
    #[allow(unused)]
    pub user_id: String,
    #[allow(unused)]
    /// Expiration timestamp in Unix epoch milliseconds.
    ///
    /// ## 繁體中文
    ///
    /// 到期時間（Unix epoch 毫秒）。
    pub expire_at: u64,
    #[allow(unused)]
    // Roles associated with the token.
    pub roles: Vec<String>,
}
