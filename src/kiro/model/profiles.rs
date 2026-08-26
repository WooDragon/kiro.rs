//! ListAvailableProfiles 响应模型与 profile ARN 选择。

use serde::Deserialize;

/// `ListAvailableProfiles` 的响应。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAvailableProfilesResponse {
    /// 可用 profile 列表。
    #[serde(default)]
    pub profiles: Vec<AvailableProfile>,
    /// 分页游标；当前 discovery 只需要首批结果。
    #[allow(dead_code)]
    pub next_token: Option<String>,
}

/// 上游 profile 元素。
///
/// 上游还会返回若干可选元数据；本地仅消费 ARN，serde 默认忽略未知字段，避免
/// 上游增添元数据时拒绝整个响应。
#[derive(Debug, Deserialize)]
pub struct AvailableProfile {
    /// CodeWhisperer profile ARN。
    pub arn: Option<String>,
}

/// 从上游候选中确定一个 profile ARN。
///
/// 仅选择 ARN region 与 `effective_api_region` 相同的候选，并以字典序打破平局。
/// 首页没有同区候选即返回 `None`；当前不猜测 `nextToken` 的分页契约。畸形 ARN 和
/// 缺 ARN 的元素被忽略，绝不让上游数据触发 panic。
pub fn select_profile_arn(
    profiles: impl IntoIterator<Item = AvailableProfile>,
    effective_api_region: &str,
) -> Option<String> {
    let mut matching = Vec::new();

    for profile in profiles {
        let Some(arn) = profile.arn else {
            continue;
        };
        if profile_arn_region(&arn) == Some(effective_api_region) {
            matching.push(arn);
        }
    }

    matching.sort();
    matching.into_iter().next()
}

/// 判断 ARN 是否具备可用于 CodeWhisperer profile 的最小结构。
///
/// 该校验只验证 ARN 结构，不限制 region，以保留用户显式配置的跨区 ARN。
pub fn is_valid_profile_arn(arn: &str) -> bool {
    profile_arn_region(arn).is_some()
}

/// Extract the region from a CodeWhisperer profile ARN without accepting malformed input.
fn profile_arn_region(arn: &str) -> Option<&str> {
    let mut parts = arn.splitn(6, ':');
    let (
        Some("arn"),
        Some(_partition),
        Some("codewhisperer"),
        Some(region),
        Some(_account),
        Some(resource),
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return None;
    };
    let profile_name = resource.strip_prefix("profile/")?;
    (!region.is_empty()
        && !_partition.is_empty()
        && !_account.is_empty()
        && !profile_name.is_empty())
    .then_some(region)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(arn: &str) -> AvailableProfile {
        AvailableProfile {
            arn: Some(arn.to_string()),
        }
    }

    #[test]
    fn deserializes_observed_response_and_ignores_unknown_fields() {
        let response: ListAvailableProfilesResponse = serde_json::from_str(
            r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a","profileName":"test","newField":true}],"nextToken":null,"futureTopLevel":{}}"#,
        )
        .unwrap();
        assert_eq!(response.profiles.len(), 1);
        assert!(response.next_token.is_none());
    }

    #[test]
    fn selects_region_then_lexical_order_without_input_order_dependence() {
        let selected = select_profile_arn(
            vec![
                profile("arn:aws:codewhisperer:eu-west-1:111111111111:profile/z"),
                profile("arn:aws:codewhisperer:us-east-1:111111111111:profile/z"),
                profile("arn:aws:codewhisperer:us-east-1:111111111111:profile/a"),
            ],
            "us-east-1",
        );
        assert_eq!(
            selected.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/a")
        );
    }

    #[test]
    fn rejects_other_regions_when_no_candidate_matches_region() {
        let selected = select_profile_arn(
            vec![
                profile("arn:aws:codewhisperer:eu-west-1:111111111111:profile/z"),
                profile("arn:aws:codewhisperer:ap-southeast-1:111111111111:profile/a"),
            ],
            "us-east-1",
        );
        assert_eq!(selected, None);
    }

    #[test]
    fn validates_only_well_formed_profile_arns() {
        assert!(is_valid_profile_arn(
            "arn:aws:codewhisperer:eu-west-1:111111111111:profile/explicit-cross-region"
        ));
        assert!(!is_valid_profile_arn(""));
        assert!(!is_valid_profile_arn("   "));
        assert!(!is_valid_profile_arn(
            "arn:aws:codewhisperer:us-east-1:111111111111:profile/"
        ));
        assert!(!is_valid_profile_arn(
            "arn::codewhisperer:us-east-1:111111111111:profile/name"
        ));
        assert!(!is_valid_profile_arn(
            "arn:aws:codewhisperer:us-east-1::profile/name"
        ));
    }

    #[test]
    fn ignores_empty_and_malformed_arns() {
        assert_eq!(
            select_profile_arn(
                vec![
                    AvailableProfile { arn: None },
                    profile("not-an-arn"),
                    profile("arn:aws:codewhisperer:us-east-1:111111111111:wrong/x"),
                    profile("arn::codewhisperer:us-east-1:111111111111:profile/name"),
                    profile("arn:aws:codewhisperer:us-east-1::profile/name"),
                    profile("arn:aws:codewhisperer:us-east-1:111111111111:profile/"),
                ],
                "us-east-1",
            ),
            None,
            "empty partition, account, or profile suffix must not be accepted"
        );
    }
}
