use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{self, ErrorKind, Read, Write};

const MAGIC: &[u8; 8] = b"VLTSTRM1";
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const AES_GCM_TAG_SIZE: usize = 16;

fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn make_nonce(base_nonce: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut nonce = *base_nonce;
    nonce[8..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn aead_to_io_error(msg: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg)
}

pub struct EncryptWriter<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    base_nonce: [u8; 12],
    counter: u32,
    buffer: Vec<u8>,
    finished: bool,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(mut inner: W, password: &str) -> io::Result<Self> {
        let key_bytes = derive_key(password);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut base_nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut base_nonce);

        inner.write_all(MAGIC)?;
        inner.write_all(&base_nonce)?;

        Ok(Self {
            inner,
            cipher,
            base_nonce,
            counter: 0,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            finished: false,
        })
    }

    fn flush_buffer_chunk(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let nonce_bytes = make_nonce(&self.base_nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, self.buffer.as_slice())
            .map_err(|_| aead_to_io_error("Falha ao criptografar bloco."))?;

        let enc_len = u32::try_from(encrypted.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Bloco criptografado muito grande."))?;
        self.inner.write_all(&enc_len.to_le_bytes())?;
        self.inner.write_all(&encrypted)?;
        self.buffer.clear();
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        if !self.finished {
            self.flush_buffer_chunk()?;
            self.inner.write_all(&0u32.to_le_bytes())?;
            self.inner.flush()?;
            self.finished = true;
        }
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let original_len = buf.len();

        while !buf.is_empty() {
            let available = CHUNK_SIZE - self.buffer.len();
            let to_copy = available.min(buf.len());
            self.buffer.extend_from_slice(&buf[..to_copy]);
            buf = &buf[to_copy..];

            if self.buffer.len() == CHUNK_SIZE {
                self.flush_buffer_chunk()?;
            }
        }

        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer_chunk()?;
        self.inner.flush()
    }
}

pub struct DecryptReader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    base_nonce: [u8; 12],
    counter: u32,
    plain_buffer: Vec<u8>,
    plain_pos: usize,
    eof: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(mut inner: R, password: &str) -> io::Result<Self> {
        let key_bytes = derive_key(password);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut magic = [0u8; 8];
        inner.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Formato de backup inválido ou incompatível.",
            ));
        }

        let mut base_nonce = [0u8; 12];
        inner.read_exact(&mut base_nonce)?;

        Ok(Self {
            inner,
            cipher,
            base_nonce,
            counter: 0,
            plain_buffer: Vec::new(),
            plain_pos: 0,
            eof: false,
        })
    }

    fn load_next_chunk(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }

        let mut len_bytes = [0u8; 4];
        self.inner.read_exact(&mut len_bytes)?;
        let enc_len = u32::from_le_bytes(len_bytes) as usize;

        if enc_len == 0 {
            self.eof = true;
            self.plain_buffer.clear();
            self.plain_pos = 0;
            return Ok(());
        }

        if enc_len < AES_GCM_TAG_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Bloco criptografado inválido.",
            ));
        }

        let mut encrypted = vec![0u8; enc_len];
        self.inner.read_exact(&mut encrypted)?;

        let nonce_bytes = make_nonce(&self.base_nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = self
            .cipher
            .decrypt(nonce, encrypted.as_slice())
            .map_err(|_| aead_to_io_error("Falha ao descriptografar: senha incorreta ou backup corrompido."))?;

        self.plain_buffer = decrypted;
        self.plain_pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.plain_pos >= self.plain_buffer.len() {
            self.load_next_chunk()?;
            if self.eof {
                return Ok(0);
            }
        }

        let remaining = &self.plain_buffer[self.plain_pos..];
        let to_copy = remaining.len().min(out.len());
        out[..to_copy].copy_from_slice(&remaining[..to_copy]);
        self.plain_pos += to_copy;
        Ok(to_copy)
    }
}
