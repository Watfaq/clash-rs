use boring_sys::MD5_DIGEST_LENGTH;

pub const ID_BYTES_LEN: usize = 16;

#[derive(Clone)]
pub struct ID {
    pub uuid: uuid::Uuid,
    pub cmd_key: [u8; MD5_DIGEST_LENGTH as _],
}

pub fn new_alter_id_list(primary: &ID, alter_id_count: u16) -> Vec<ID> {
    let mut alter_id_list = Vec::with_capacity(alter_id_count as usize);
    let mut prev_id = primary.uuid;

    for _ in 0..alter_id_count {
        let new_id = next_id(&prev_id);
        alter_id_list.push(ID {
            uuid: new_id,
            cmd_key: primary.cmd_key.clone(),
        });
        prev_id = new_id;
    }

    alter_id_list.push(primary.to_owned());
    alter_id_list
}

pub fn new_id(uuid: &uuid::Uuid) -> ID {
    let uuid = uuid.to_owned();
    let mut cmd_key = [0u8; MD5_DIGEST_LENGTH as _];

    let mut ctx = boring_sys::MD5_CTX::default();
    unsafe {
        boring_sys::MD5_Init(&mut ctx as _);
        boring_sys::MD5_Update(
            &mut ctx as _,
            uuid.as_bytes().as_ptr() as _,
            uuid.as_bytes().len(),
        );
        boring_sys::MD5_Update(
            &mut ctx as _,
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21".as_ptr() as _,
            36,
        );
        boring_sys::MD5_Final(cmd_key.as_mut_ptr() as _, &mut ctx as _);
    }

    ID { uuid, cmd_key }
}

fn next_id(i: &uuid::Uuid) -> uuid::Uuid {
    let mut ctx = boring_sys::MD5_CTX::default();
    unsafe {
        boring_sys::MD5_Init(&mut ctx as _);
        boring_sys::MD5_Update(
            &mut ctx as _,
            i.as_bytes().as_ptr() as _,
            i.as_bytes().len(),
        );
        boring_sys::MD5_Update(
            &mut ctx as _,
            b"b48619fe-8f02-49e0-b9e9-edf763e17e21".as_ptr() as _,
            36,
        );
        let mut buf = [0u8; MD5_DIGEST_LENGTH as _];
        loop {
            boring_sys::MD5_Final(buf.as_mut_ptr() as _, &mut ctx as _);
            if i.as_bytes() != buf.as_slice() {
                return uuid::Uuid::from_bytes(buf);
            }

            boring_sys::MD5_Update(
                &mut ctx as _,
                b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2".as_ptr() as _,
                36,
            );
        }
    }
}
