/// ## 日本語
///
/// メモリに保存される token のメタデータです。
///
/// token 文字列に紐づく内部レコードです。
///
/// ## English
///
/// Token metadata stored in memory.
///
/// This is an internal record associated with a token string.
#[derive(Clone)]
#[cfg_attr(feature = "rbac", derive(serde::Serialize, serde::Deserialize))]
pub struct RTokenInfo {
    /// ## 日本語
    ///
    /// token に紐づくユーザー ID。
    ///
    /// ## English
    ///
    /// User id associated with the token.
    #[allow(unused)]
    pub user_id: String,
    #[allow(unused)]
    /// ## 日本語
    ///
    /// 有効期限（Unix epoch ミリ秒）。
    ///
    /// ## English
    ///
    /// Expiration timestamp in Unix epoch milliseconds.
    pub expire_at: u64,
    #[allow(unused)]
    // Roles associated with the token.
    pub roles: Vec<String>,
}
