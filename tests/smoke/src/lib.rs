#[cfg(test)]
mod tests {
    #[test]
    fn client_payload() {
        assert_eq!(gp_client::TEEC_CONFIG_PAYLOAD_REF_COUNT, 4);
    }
}
