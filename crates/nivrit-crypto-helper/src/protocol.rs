use super::{err, Request, Response};

pub(crate) fn handle(input: &str, dispatch: impl FnOnce(Request) -> Response) -> String {
    let response = match input.trim() {
        "" => err("empty input"),
        input => match serde_json::from_str(input) {
            Ok(request) => dispatch(request),
            Err(error) => err(format!("parse request: {error}")),
        },
    };
    serde_json::to_string(&response).expect("protocol response is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_stays_inside_protocol_interface() {
        assert!(handle("", |_| unreachable!()).contains("empty input"));
        assert!(handle("{}", |_| unreachable!()).contains("parse request"));
    }
}
