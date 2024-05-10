use md5::Digest;

#[derive(Clone)]
pub struct ID {
    pub uuid: uuid::Uuid,
    pub cmd_key: [u8; 16],
}

pub fn new_alter_id_list(primary: &ID, alter_id_count: u16) -> Vec<ID> {
    let mut alter_id_list = Vec::with_capacity(alter_id_count as usize);
    let mut prev_id = primary.uuid;

    for _ in 0..alter_id_count {
        let new_id = next_id(&prev_id);
        alter_id_list.push(ID {
            uuid: new_id,
            cmd_key: primary.cmd_key,
        });
        prev_id = new_id;
    }

    alter_id_list.push(primary.to_owned());
    alter_id_list
}

/// TODO docs
pub fn new_id(uuid: &uuid::Uuid) -> ID {
    let uuid = uuid.to_owned();
    let mut hasher = md5::Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21"); // What?
    let cmd_key: [u8; 16] = hasher.finalize().into();
    ID { uuid, cmd_key }
}

/// TODO docs
fn next_id(i: &uuid::Uuid) -> uuid::Uuid {
    let mut hasher = md5::Md5::new();
    hasher.update(i.as_bytes());
    hasher.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81"); // Why?
    let buf: [u8; 16] = hasher.finalize().into();
    uuid::Uuid::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new_id() {
        let id =
            super::new_id(&uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap());
        assert_eq!(id.uuid.to_string(), "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(
            id.cmd_key,
            [181, 13, 145, 106, 192, 206, 192, 103, 152, 26, 248, 229, 243, 138, 117, 143]
        );
    }

    #[test]
    fn test_next_id() {
        let id =
            super::new_id(&uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap());
        let next_id = super::next_id(&id.uuid);
        assert_eq!(next_id.to_string(), "5a071834-12d5-980a-72ac-845d5568d17d");
    }
}
