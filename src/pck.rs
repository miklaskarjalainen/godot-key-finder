pub struct PckFile {
    bytes: Vec<u8>,
    current_index: usize,
}

impl PckFile {
    pub fn new(file_path: &str) -> PckFile {
        let file = std::fs::read(file_path).expect("?");
        PckFile {
            bytes: file,
            current_index: 0,
        }
    }

    pub fn read_buffer(&mut self, buffer: &mut [u8], big_endian: bool) {
        let iter_with_endian = 0..buffer.len();

        for i in iter_with_endian {
            let with_endian = if big_endian { buffer.len() - i - 1 } else { i };
            buffer[with_endian] = self.bytes[self.current_index + i];
        }
        self.current_index += buffer.len();
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut buffer = [0u8; 4];
        self.read_buffer(&mut buffer, false);
        u32::from_le_bytes(buffer)
    }

    pub fn read_u64(&mut self) -> u64 {
        let mut buffer = [0u8; 8];
        self.read_buffer(&mut buffer, false);
        u64::from_le_bytes(buffer)
    }

    pub fn skip_bytes(&mut self, count: usize) {
        self.current_index += count;
    }
}

pub struct DecryptContext {
    encrypted_data: Vec<u8>,
    real_length: usize, // encrypted data is 16 aligned
    data_copy: Vec<u8>, // using this to run the cypher on, without modifying the original.
    data_md5: [u8; 16],
    iv: [u8; 16],
}

impl DecryptContext {
    pub fn from(mut pck: PckFile) -> DecryptContext {
        pck.read_u32(); // magic
        pck.read_u32(); // version
        pck.read_u32(); // major
        pck.read_u32(); // minor
        pck.read_u32(); // patch
        pck.read_u32(); // pack_flags
        pck.read_u64(); // file_base
        pck.skip_bytes(size_of::<u32>() * 16); // reserved
        pck.read_u32(); // file_count

        let mut md5hash = [0u8; 16];
        pck.read_buffer(&mut md5hash, false);
        let length = pck.read_u64();
        let mut iv = [0u8; 16];
        pck.read_buffer(&mut iv, false);

        let length_aligned = {
            if length % 16 != 0 {
                length + (16 - (length % 16))
            } else {
                length
            }
        } as usize;

        let mut data: Vec<u8> = vec![];
        data.resize(length_aligned, 0u8);
        pck.read_buffer(&mut data, false);

        DecryptContext {
            encrypted_data: data.clone(),
            real_length: length as usize,
            data_md5: md5hash,
            data_copy: data,
            iv: iv,
        }
    }

    /**
     * @brief returns `true` if encryption was successful.
     */
    pub fn try_decrypt(&mut self, key: &[u8]) -> bool {
        use aes::cipher::{AsyncStreamCipher, KeyIvInit};
        assert_eq!(key.len(), 32, "invalid key length");

        // decrypt
        type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;
        Aes256CfbDec::new(key.into(), &self.iv.into())
            .decrypt_b2b(&self.encrypted_data, &mut self.data_copy)
            .expect("?");

        //
        let hash = md5::compute(&self.data_copy[0..self.real_length]);

        &hash.0 == &self.data_md5
    }
}
